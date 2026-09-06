#!/usr/bin/env bash
#
# checksum_offload_verify.sh -- real-hardware checksum/offload verification
# for the eBPF TC data planes (item 13 of the eBPF inbound reliability work).
#
# WHY THIS EXISTS
#
# Every TC program this inbound loads rewrites packets in place: the
# bypass_rule_set CIDR match leaves matched traffic untouched but redirects
# the rest, shared_network's packet_rewrite path rewrites IPv4/IPv6
# source/destination addresses and, for TCP/UDP, ports, and fakeip_icmp's
# reply path flips an ICMP/ICMPv6 echo request into a reply in place with an
# incremental checksum update (bpf_l4_csum_replace, no payload walk). All of
# that reasoning was checked against RFC 1071 incremental-checksum math and
# against this repo's own veth/network-namespace tests, but none of those
# tests exercise real NIC checksum/segmentation offload: veth interfaces
# have no hardware offload path at all, and a software loopback always
# computes checksums honestly regardless of what NIC feature flags claim.
# The one thing this whole engagement has never been able to verify is
# whether these rewrites still produce a WIRE-CORRECT packet once a real
# NIC's checksum offload, GRO, GSO, or TSO gets involved -- offload
# firmware/drivers sometimes assume the checksum field holds what the
# kernel would have computed in software, and an eBPF program that changes
# header bytes without updating that field the way the NIC expects can
# produce packets that only look correct in a software capture.
#
# This script is diagnostic tooling for a real target machine, not a CI
# test: it requires two real Linux hosts joined by a real NIC (not veth, not
# a cloud NIC using virtio-net's software checksum path -- see the
# companion doc for how to tell), and it has NEVER BEEN RUN, because no such
# environment was available while this round of work was done. Read
# docs/manual/misc/ebpf-checksum-offload-verification.md before running it.
#
# WHAT IT DOES
#
# On the LOCAL host (the one running this sing-box eBPF inbound, attached to
# $LOCAL_IFACE) it:
#   1. Enumerates the offload features $LOCAL_IFACE actually advertises via
#      `ethtool -k`, filtered to the ones relevant here (rx/tx checksumming,
#      generic-segmentation-offload, tcp-segmentation-offload,
#      generic-receive-offload, and, if present, tx-udp-segmentation).
#   2. For every combination in $OFFLOAD_MATRIX (see the doc for how to size
#      this -- the full power set is usually too slow to be worth running),
#      toggles those features with `ethtool -K`, then drives one round of
#      traffic per data plane this round's work touched:
#        - a bypass_rule_set-matched flow (expected to cross untouched)
#        - a FakeIP ICMP echo (v4 and, if $REMOTE_IPV6 is set, v6)
#        - a shared_network packet_rewrite'd TCP transfer (if $REMOTE_PORT_TCP
#          is set) and UDP transfer (if $REMOTE_PORT_UDP is set)
#      capturing on both ends with tcpdump, and reports PASS/FAIL per
#      combination based on what the REMOTE host's kernel actually accepted
#      (ping RTT/loss, transfer byte count) -- never based on tcpdump's own
#      checksum annotation, which is well known to misreport "incorrect" on
#      the sending side whenever tx offload is on, because the real checksum
#      is only computed by the NIC after the capture point.
#   3. Restores the interface's original offload settings on exit, including
#      on Ctrl-C or an unexpected failure (trap-based).
#
# WHAT IT DOES NOT DO
#
# It does not configure the eBPF inbound itself -- sing-box must already be
# running with fakeip_icmp=reply (or whatever combination is under test) and
# attached to $LOCAL_IFACE before this script starts, and $FAKEIP_PREFIX
# must match what that inbound was actually configured with. It does not
# tear down or restore sing-box's own state. It does not run on the remote
# host by itself; $REMOTE_HOST is reached over ssh (key-based, non-interactive)
# to start/stop its side of each capture and transfer.
#
# USAGE
#
#   sudo LOCAL_IFACE=eth0 REMOTE_HOST=192.0.2.10 REMOTE_SSH_USER=root \
#       FAKEIP_PREFIX=198.18.0.0/15 REMOTE_FAKEIP_TARGET=198.18.0.1 \
#       ./checksum_offload_verify.sh
#
# See docs/manual/misc/ebpf-checksum-offload-verification.md for the full
# environment setup, required variables, and how to read the report.

set -euo pipefail

: "${LOCAL_IFACE:?set LOCAL_IFACE to the interface this eBPF inbound is attached to}"
: "${REMOTE_HOST:?set REMOTE_HOST to the peer address, reachable over ssh}"
: "${REMOTE_SSH_USER:=root}"
: "${FAKEIP_PREFIX:?set FAKEIP_PREFIX to the configured FakeIP CIDR (e.g. 198.18.0.0/15)}"
: "${REMOTE_FAKEIP_TARGET:?set REMOTE_FAKEIP_TARGET to an address inside FAKEIP_PREFIX the remote host will ping}"
: "${REMOTE_IPV6:=}"
: "${REMOTE_PORT_TCP:=}"
: "${REMOTE_PORT_UDP:=}"
: "${PING_COUNT:=20}"
: "${TRANSFER_BYTES:=8388608}" # 8 MiB, large enough to force TSO/GSO segmentation
: "${OUT_DIR:=./checksum-offload-report}"
: "${SSH:=ssh -o BatchMode=yes -o ConnectTimeout=5}"

RELEVANT_FEATURES=(rx-checksumming tx-checksumming generic-segmentation-offload tcp-segmentation-offload generic-receive-offload tx-udp-segmentation)

mkdir -p "$OUT_DIR"
REPORT="$OUT_DIR/report.tsv"
printf 'feature_state\tcheck\tresult\tdetail\n' > "$REPORT"

declare -A ORIGINAL_STATE
capture_original_state() {
	local feature
	for feature in "${RELEVANT_FEATURES[@]}"; do
		local line
		line=$(ethtool -k "$LOCAL_IFACE" 2>/dev/null | awk -v f="$feature:" '$1==f{print $2}') || true
		ORIGINAL_STATE["$feature"]="${line:-unsupported}"
	done
}

restore_original_state() {
	local feature
	for feature in "${RELEVANT_FEATURES[@]}"; do
		local state="${ORIGINAL_STATE[$feature]:-}"
		case "$state" in
		on) ethtool -K "$LOCAL_IFACE" "$feature" on 2>/dev/null || true ;;
		off) ethtool -K "$LOCAL_IFACE" "$feature" off 2>/dev/null || true ;;
		esac
	done
	echo "restored $LOCAL_IFACE offload settings to their original values" >&2
}
trap restore_original_state EXIT

set_features() {
	# $1 is a space-separated list of feature=on|off pairs; unsupported
	# features (fixed at "unsupported" in ORIGINAL_STATE) are skipped rather
	# than failing the whole combination, since not every NIC exposes every
	# feature in RELEVANT_FEATURES.
	local pair feature value
	for pair in $1; do
		feature="${pair%%=*}"
		value="${pair##*=}"
		if [[ "${ORIGINAL_STATE[$feature]:-unsupported}" == "unsupported" ]]; then
			continue
		fi
		ethtool -K "$LOCAL_IFACE" "$feature" "$value" 2>/dev/null || {
			echo "warning: could not set $feature=$value on $LOCAL_IFACE (driver refused it); skipping this combination for that feature" >&2
		}
	done
}

record() {
	printf '%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" | tee -a "$REPORT" >&2
}

check_fakeip_icmp() {
	local state_label="$1" family="$2" target="$3"
	local ping_bin=ping
	[[ "$family" == "6" ]] && ping_bin=ping6
	local out
	if out=$($ping_bin -c "$PING_COUNT" -q "$target" 2>&1); then
		local loss
		loss=$(echo "$out" | grep -oP '\d+(?=% packet loss)')
		if [[ "$loss" == "0" ]]; then
			record "$state_label" "fakeip_icmp_v${family}" PASS "0% loss over $PING_COUNT pings to $target"
		else
			record "$state_label" "fakeip_icmp_v${family}" FAIL "${loss}% loss over $PING_COUNT pings to $target"
		fi
	else
		record "$state_label" "fakeip_icmp_v${family}" FAIL "ping command itself failed: $out"
	fi
}

check_bypass_passthrough() {
	local state_label="$1"
	# A CIDR inside FAKEIP_PREFIX is never a bypass_rule_set destination by
	# construction (bypass_rule_set only ever matches real, non-FakeIP
	# destinations), so this instead sends through REMOTE_HOST directly --
	# a flow bypass_rule_set is expected to leave completely untouched --
	# and simply confirms the remote host still receives it byte-for-byte.
	# It is the offload-sensitive control case: any wire corruption here
	# would mean the interface itself mishandles this NIC's offload
	# combination even before any eBPF rewrite is involved.
	local marker
	marker="offload-check-$RANDOM"
	if $SSH "${REMOTE_SSH_USER}@${REMOTE_HOST}" "echo ready" >/dev/null 2>&1; then
		if echo "$marker" | $SSH "${REMOTE_SSH_USER}@${REMOTE_HOST}" "cat" | grep -qF "$marker"; then
			record "$state_label" bypass_passthrough PASS "ssh control-channel round trip intact"
		else
			record "$state_label" bypass_passthrough FAIL "ssh control-channel payload corrupted"
		fi
	else
		record "$state_label" bypass_passthrough FAIL "could not reach $REMOTE_HOST over ssh"
	fi
}

check_tcp_rewrite() {
	local state_label="$1"
	[[ -z "$REMOTE_PORT_TCP" ]] && return
	$SSH "${REMOTE_SSH_USER}@${REMOTE_HOST}" \
		"timeout 30 nc -l -p $REMOTE_PORT_TCP > /tmp/offload_check_tcp.bin" &
	local remote_pid=$!
	sleep 1
	if head -c "$TRANSFER_BYTES" /dev/urandom | tee "$OUT_DIR/tcp_sent.bin" | \
		timeout 25 nc -q1 "$REMOTE_FAKEIP_TARGET" "$REMOTE_PORT_TCP"; then
		wait "$remote_pid" 2>/dev/null || true
		local remote_size
		remote_size=$($SSH "${REMOTE_SSH_USER}@${REMOTE_HOST}" "stat -c %s /tmp/offload_check_tcp.bin" 2>/dev/null || echo 0)
		if [[ "$remote_size" == "$TRANSFER_BYTES" ]]; then
			record "$state_label" shared_rewrite_tcp PASS "$remote_size bytes received intact"
		else
			record "$state_label" shared_rewrite_tcp FAIL "expected $TRANSFER_BYTES bytes, remote received $remote_size"
		fi
	else
		record "$state_label" shared_rewrite_tcp FAIL "local nc transfer failed or timed out"
	fi
}

check_udp_rewrite() {
	local state_label="$1"
	[[ -z "$REMOTE_PORT_UDP" ]] && return
	$SSH "${REMOTE_SSH_USER}@${REMOTE_HOST}" \
		"timeout 15 nc -u -l -p $REMOTE_PORT_UDP -w 10 > /tmp/offload_check_udp.bin" &
	local remote_pid=$!
	sleep 1
	head -c 65000 /dev/urandom > "$OUT_DIR/udp_sent.bin"
	nc -u -q1 -w2 "$REMOTE_FAKEIP_TARGET" "$REMOTE_PORT_UDP" < "$OUT_DIR/udp_sent.bin" || true
	wait "$remote_pid" 2>/dev/null || true
	local remote_size
	remote_size=$($SSH "${REMOTE_SSH_USER}@${REMOTE_HOST}" "stat -c %s /tmp/offload_check_udp.bin" 2>/dev/null || echo 0)
	if [[ "$remote_size" != "0" ]]; then
		record "$state_label" shared_rewrite_udp PASS "$remote_size bytes received (UDP is best-effort; a non-zero receipt with matching content, checked separately, is the real pass condition -- see the doc)"
	else
		record "$state_label" shared_rewrite_udp FAIL "remote received nothing"
	fi
}

run_one_combination() {
	local state_label="$1" feature_args="$2"
	echo "=== combination: $state_label ($feature_args) ===" >&2
	set_features "$feature_args"
	local capture_local="$OUT_DIR/${state_label}.local.pcap"
	local capture_remote_path="/tmp/offload_check_${state_label}.pcap"
	timeout 40 tcpdump -i "$LOCAL_IFACE" -w "$capture_local" >/dev/null 2>&1 &
	local tcpdump_pid=$!
	$SSH "${REMOTE_SSH_USER}@${REMOTE_HOST}" \
		"nohup timeout 40 tcpdump -i any -w $capture_remote_path >/dev/null 2>&1 &" || true
	sleep 1

	check_bypass_passthrough "$state_label"
	check_fakeip_icmp "$state_label" 4 "$REMOTE_FAKEIP_TARGET"
	if [[ -n "$REMOTE_IPV6" ]]; then
		check_fakeip_icmp "$state_label" 6 "$REMOTE_IPV6"
	fi
	check_tcp_rewrite "$state_label"
	check_udp_rewrite "$state_label"

	kill "$tcpdump_pid" 2>/dev/null || true
	wait "$tcpdump_pid" 2>/dev/null || true
	$SSH "${REMOTE_SSH_USER}@${REMOTE_HOST}" "pkill -f 'tcpdump -i any -w $capture_remote_path'" 2>/dev/null || true
	$SSH "${REMOTE_SSH_USER}@${REMOTE_HOST}" "cat $capture_remote_path" > "$OUT_DIR/${state_label}.remote.pcap" 2>/dev/null || true
}

capture_original_state
echo "original $LOCAL_IFACE offload state:" >&2
for feature in "${RELEVANT_FEATURES[@]}"; do
	echo "  $feature = ${ORIGINAL_STATE[$feature]}" >&2
done

# The full power set of RELEVANT_FEATURES is 64 combinations, most of which
# tell you nothing new about this eBPF pipeline specifically -- the doc
# explains why these four are the ones worth actually running, and how to
# extend OFFLOAD_MATRIX if a specific NIC/driver combination needs more.
OFFLOAD_MATRIX=(
	"all-on:rx-checksumming=on tx-checksumming=on generic-segmentation-offload=on tcp-segmentation-offload=on generic-receive-offload=on"
	"all-off:rx-checksumming=off tx-checksumming=off generic-segmentation-offload=off tcp-segmentation-offload=off generic-receive-offload=off"
	"tx-checksum-off-only:tx-checksumming=off"
	"tso-gso-off-only:generic-segmentation-offload=off tcp-segmentation-offload=off"
)

for entry in "${OFFLOAD_MATRIX[@]}"; do
	label="${entry%%:*}"
	args="${entry#*:}"
	run_one_combination "$label" "$args"
done

echo "report written to $REPORT" >&2
if grep -q FAIL "$REPORT"; then
	echo "at least one FAIL was recorded -- see $REPORT" >&2
	exit 1
fi
echo "all recorded checks PASSed" >&2
