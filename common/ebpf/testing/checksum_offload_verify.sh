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
# test: it requires two or three real Linux hosts joined by a real NIC (not
# veth, not a cloud NIC using virtio-net's software checksum path -- see the
# companion doc for how to tell), and it has NEVER BEEN RUN, because no such
# environment was available while this round of work was done. Read
# docs/manual/misc/ebpf-checksum-offload-verification.md before running it.
#
# ROLES
#
# This script distinguishes three roles, which an independent review found
# an earlier version of it did not: traffic this box (the DUT, the one
# running sing-box and where this script itself runs, attached to
# $LOCAL_IFACE) originates itself only ever exercises the local.data_plane
# TC egress classifier, never shared.data_plane's ingress classifier --
# those intercept traffic arriving FROM a real downstream client, not
# traffic the DUT sends. Verifying shared.data_plane therefore needs a
# genuinely separate host to originate that traffic from:
#   - DUT: this host, running the eBPF inbound under test.
#   - $REMOTE_HOST: a real, non-FakeIP destination the DUT can reach, used
#     only for the bypass_rule_set control case (a flow bypass_rule_set is
#     expected to leave completely untouched) and, if local.data_plane's own
#     TCP/UDP/ICMP checks are requested, as the thing the DUT itself talks
#     to through its own local egress path.
#   - $DOWNSTREAM_HOST (only needed to check shared.data_plane): a separate
#     host reachable from the DUT's shared-facing interface, standing in for
#     a real LAN client. Every shared.data_plane check in this script is
#     driven FROM this host, toward the FakeIP target, over ssh -- never
#     from the DUT itself, which would silently degrade into re-testing
#     local.data_plane's own code path instead of shared.data_plane's.
#
# If both local.data_plane and shared.data_plane are enabled on the DUT at
# the same time, a downstream-originated reply is not, on its own, proof
# that shared.data_plane specifically handled it: FakeIPICMPReplies and the
# other counters this script can read from the DUT's own /ebpf diagnostics
# endpoint (see DUT_DIAGNOSTICS_URL below) are summed across every data
# plane hosting fakeip_icmp, not broken down per role. Run this script
# against a DUT configuration with only the role under test enabled if that
# ambiguity matters for the report.
#
# WHAT IT DOES
#
# On the DUT it:
#   1. Enumerates the offload features $LOCAL_IFACE actually advertises via
#      `ethtool -k`, filtered to the ones relevant here (rx/tx checksumming,
#      generic-segmentation-offload, tcp-segmentation-offload,
#      generic-receive-offload, and, if present, tx-udp-segmentation).
#   2. For every combination in $OFFLOAD_MATRIX (see the doc for how to size
#      this -- the full power set is usually too slow to be worth running),
#      sets every one of RELEVANT_FEATURES to that combination's own
#      explicit value (every combination is complete and self-contained --
#      an earlier version of this script let combinations that named only
#      the features they cared about silently inherit whatever the
#      *previous* combination left behind, so "tx checksum off, everything
#      else on" and "tx checksum off, everything else however the last
#      combination left it" were impossible to tell apart from the report
#      alone), reads each feature back with `ethtool -k` afterward, and
#      records the whole combination UNSUPPORTED rather than running any
#      check under a misleading label if the interface did not actually end
#      up in the state the combination's name claims (an unsupported
#      feature, or the driver silently refusing a change, both looked
#      identical to success in that earlier version).
#   3. For a combination that was actually applied, drives:
#        - a bypass_rule_set-matched flow (expected to cross untouched),
#          from the DUT itself, toward $REMOTE_HOST
#        - local.data_plane's own FakeIP ICMP echo and TCP/UDP checks (if
#          requested), from the DUT itself
#        - shared.data_plane's own FakeIP ICMP echo and TCP/UDP checks (if
#          $DOWNSTREAM_HOST is set), driven from that host, never the DUT
#      capturing on the DUT with tcpdump, and reports PASS/FAIL per
#      combination based on what the receiving side's kernel actually
#      accepted (ping RTT/loss, transfer byte count, and, for
#      shared.data_plane checks, the DUT's own counters if
#      DUT_DIAGNOSTICS_URL is set) -- never based on tcpdump's own checksum
#      annotation, which is well known to misreport "incorrect" on the
#      sending side whenever tx offload is on, because the real checksum is
#      only computed by the NIC after the capture point.
#   4. Restores the interface's original offload settings on exit, including
#      on Ctrl-C or an unexpected failure (trap-based).
#
# WHAT IT DOES NOT DO
#
# It does not configure the eBPF inbound itself -- sing-box must already be
# running with fakeip_icmp=reply (or whatever combination is under test) and
# attached to $LOCAL_IFACE before this script starts, and $FAKEIP_PREFIX
# must match what that inbound was actually configured with. It does not
# tear down or restore sing-box's own state. It does not run on any other
# host by itself; $REMOTE_HOST and $DOWNSTREAM_HOST are reached over ssh
# (key-based, non-interactive) to start/stop their side of each capture and
# transfer.
#
# USAGE
#
#   sudo LOCAL_IFACE=eth0 REMOTE_HOST=192.0.2.10 REMOTE_SSH_USER=root \
#       DOWNSTREAM_HOST=192.0.2.20 DOWNSTREAM_SSH_USER=root \
#       DUT_DIAGNOSTICS_URL=http://127.0.0.1:9090/ebpf \
#       FAKEIP_PREFIX=198.18.0.0/15 REMOTE_FAKEIP_TARGET=198.18.0.1 \
#       ./checksum_offload_verify.sh
#
# DOWNSTREAM_HOST, and everything under it, is optional -- omit it to check
# only local.data_plane, exactly as an earlier version of this script always
# did. See docs/manual/misc/ebpf-checksum-offload-verification.md for the
# full environment setup, required variables, and how to read the report.

set -euo pipefail

: "${LOCAL_IFACE:?set LOCAL_IFACE to the interface this eBPF inbound is attached to}"
: "${REMOTE_HOST:?set REMOTE_HOST to the peer address, reachable over ssh}"
: "${REMOTE_SSH_USER:=root}"
: "${DOWNSTREAM_HOST:=}"
: "${DOWNSTREAM_SSH_USER:=$REMOTE_SSH_USER}"
: "${DUT_DIAGNOSTICS_URL:=}"
: "${DUT_DIAGNOSTICS_TOKEN:=}"
: "${FAKEIP_PREFIX:?set FAKEIP_PREFIX to the configured FakeIP CIDR (e.g. 198.18.0.0/15)}"
: "${REMOTE_FAKEIP_TARGET:?set REMOTE_FAKEIP_TARGET to an address inside FAKEIP_PREFIX the remote host will ping}"
: "${REMOTE_IPV6:=}"
: "${REMOTE_PORT_TCP:=}"
: "${REMOTE_PORT_UDP:=}"
: "${PING_COUNT:=20}"
: "${TRANSFER_BYTES:=8388608}" # 8 MiB, large enough to force TSO/GSO segmentation
: "${OUT_DIR:=./checksum-offload-report}"
: "${SSH:=ssh -o BatchMode=yes -o ConnectTimeout=5}"
: "${DOWNSTREAM_SSH:=ssh -o BatchMode=yes -o ConnectTimeout=5}"

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

# actual_feature_state reads back what ethtool -k now reports for $1,
# stripped of any trailing "[fixed]"/"[requested ...]" annotation, so a
# combination's own requested value can be compared against it directly.
actual_feature_state() {
	ethtool -k "$LOCAL_IFACE" 2>/dev/null | awk -v f="$1:" '$1==f{print $2}'
}

# set_features applies every entry in $1 (a space-separated list of
# feature=on|off pairs) and sets the global COMBINATION_OK to 0 if any of
# them -- unsupported on this NIC, refused by the driver, or silently not
# taking effect -- did not actually leave the interface in the requested
# state. $1 must cover every entry in RELEVANT_FEATURES: this function does
# not reset anything to a baseline first, so a combination that only names
# the features it cares about would otherwise silently inherit whatever the
# previous combination left every other feature at.
COMBINATION_OK=1
set_features() {
	COMBINATION_OK=1
	local pair feature value actual
	for pair in $1; do
		feature="${pair%%=*}"
		value="${pair##*=}"
		if [[ "${ORIGINAL_STATE[$feature]:-unsupported}" == "unsupported" ]]; then
			echo "warning: $feature is not supported on $LOCAL_IFACE; this combination cannot be fully applied" >&2
			COMBINATION_OK=0
			continue
		fi
		if ! ethtool -K "$LOCAL_IFACE" "$feature" "$value" 2>/dev/null; then
			echo "warning: could not set $feature=$value on $LOCAL_IFACE (driver refused it)" >&2
			COMBINATION_OK=0
			continue
		fi
		actual=$(actual_feature_state "$feature")
		if [[ "$actual" != "$value"* ]]; then
			echo "warning: requested $feature=$value on $LOCAL_IFACE but ethtool now reports '$actual'" >&2
			COMBINATION_OK=0
		fi
	done
}

# require_complete_combination fails loudly, before anything is ever
# applied, if an OFFLOAD_MATRIX entry does not mention every feature in
# RELEVANT_FEATURES -- catching an incomplete combination at definition
# time instead of letting it silently inherit leftover state at run time.
require_complete_combination() {
	local label="$1" args="$2" feature
	for feature in "${RELEVANT_FEATURES[@]}"; do
		if [[ "$args" != *"$feature="* ]]; then
			echo "OFFLOAD_MATRIX entry '$label' does not mention $feature; every combination must set every entry in RELEVANT_FEATURES explicitly" >&2
			exit 1
		fi
	done
}

record() {
	printf '%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" | tee -a "$REPORT" >&2
}

# dut_counter reads one field under .ebpf[0].counters from the DUT's own
# /ebpf diagnostics endpoint (see docs/manual/misc/ebpf-troubleshooting.md),
# or prints nothing if DUT_DIAGNOSTICS_URL is not set. $1 is a jq filter
# fragment, e.g. ".fakeip_icmp_replies".
dut_counter() {
	[[ -z "$DUT_DIAGNOSTICS_URL" ]] && return
	local auth=()
	[[ -n "$DUT_DIAGNOSTICS_TOKEN" ]] && auth=(-H "Authorization: Bearer $DUT_DIAGNOSTICS_TOKEN")
	curl -fsS "${auth[@]}" "$DUT_DIAGNOSTICS_URL" 2>/dev/null | jq -r ".ebpf[0].counters$1 // empty" 2>/dev/null
}

check_local_fakeip_icmp() {
	local state_label="$1" family="$2" target="$3"
	local ping_bin=ping
	[[ "$family" == "6" ]] && ping_bin=ping6
	local out
	if out=$($ping_bin -c "$PING_COUNT" -q "$target" 2>&1); then
		local loss
		loss=$(echo "$out" | grep -oP '\d+(?=% packet loss)')
		if [[ "$loss" == "0" ]]; then
			record "$state_label" "local_fakeip_icmp_v${family}" PASS "0% loss over $PING_COUNT pings to $target, originated from the DUT itself"
		else
			record "$state_label" "local_fakeip_icmp_v${family}" FAIL "${loss}% loss over $PING_COUNT pings to $target"
		fi
	else
		record "$state_label" "local_fakeip_icmp_v${family}" FAIL "ping command itself failed: $out"
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

check_local_tcp_rewrite() {
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
			record "$state_label" local_shared_rewrite_tcp PASS "$remote_size bytes received intact, originated from the DUT itself"
		else
			record "$state_label" local_shared_rewrite_tcp FAIL "expected $TRANSFER_BYTES bytes, remote received $remote_size"
		fi
	else
		record "$state_label" local_shared_rewrite_tcp FAIL "local nc transfer failed or timed out"
	fi
}

check_local_udp_rewrite() {
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
		record "$state_label" local_shared_rewrite_udp PASS "$remote_size bytes received (UDP is best-effort; a non-zero receipt with matching content, checked separately, is the real pass condition -- see the doc), originated from the DUT itself"
	else
		record "$state_label" local_shared_rewrite_udp FAIL "remote received nothing"
	fi
}

# check_shared_fakeip_icmp is check_local_fakeip_icmp's shared.data_plane
# counterpart: the ping is originated from $DOWNSTREAM_HOST over ssh, never
# from the DUT, since shared.data_plane only ever sees traffic arriving from
# a real downstream client -- a DUT-originated ping proves nothing about it.
# When DUT_DIAGNOSTICS_URL is set, this also requires the DUT's own
# fakeip_icmp_replies counter to have actually advanced, which is real
# evidence the packet was processed by this inbound's eBPF code specifically
# and not, say, answered by some unrelated device on the same segment.
check_shared_fakeip_icmp() {
	local state_label="$1" family="$2" target="$3"
	[[ -z "$DOWNSTREAM_HOST" ]] && return
	local ping_bin=ping
	[[ "$family" == "6" ]] && ping_bin=ping6
	local before after out
	before=$(dut_counter .fakeip_icmp_replies)
	if out=$($DOWNSTREAM_SSH "${DOWNSTREAM_SSH_USER}@${DOWNSTREAM_HOST}" "$ping_bin -c $PING_COUNT -q $target" 2>&1); then
		after=$(dut_counter .fakeip_icmp_replies)
		local loss
		loss=$(echo "$out" | grep -oP '\d+(?=% packet loss)')
		if [[ "$loss" != "0" ]]; then
			record "$state_label" "shared_fakeip_icmp_v${family}" FAIL "${loss}% loss over $PING_COUNT pings to $target from $DOWNSTREAM_HOST"
			return
		fi
		if [[ -n "$DUT_DIAGNOSTICS_URL" ]]; then
			if [[ -z "$before" || -z "$after" || "$after" -le "$before" ]]; then
				record "$state_label" "shared_fakeip_icmp_v${family}" FAIL "0% loss from $DOWNSTREAM_HOST, but the DUT's fakeip_icmp_replies counter did not advance (before=$before after=$after) -- something other than this inbound answered"
				return
			fi
			record "$state_label" "shared_fakeip_icmp_v${family}" PASS "0% loss over $PING_COUNT pings to $target from $DOWNSTREAM_HOST; DUT fakeip_icmp_replies advanced $before -> $after"
		else
			record "$state_label" "shared_fakeip_icmp_v${family}" PASS "0% loss over $PING_COUNT pings to $target from $DOWNSTREAM_HOST (DUT_DIAGNOSTICS_URL not set: this does not confirm shared.data_plane specifically answered, only that something did)"
		fi
	else
		record "$state_label" "shared_fakeip_icmp_v${family}" FAIL "ping from $DOWNSTREAM_HOST itself failed: $out"
	fi
}

# check_shared_tcp_rewrite is check_local_tcp_rewrite's shared.data_plane
# counterpart: the transfer is driven from $DOWNSTREAM_HOST toward
# REMOTE_FAKEIP_TARGET, with the DUT in between doing the actual rewrite.
check_shared_tcp_rewrite() {
	local state_label="$1"
	[[ -z "$DOWNSTREAM_HOST" || -z "$REMOTE_PORT_TCP" ]] && return
	$SSH "${REMOTE_SSH_USER}@${REMOTE_HOST}" \
		"timeout 30 nc -l -p $REMOTE_PORT_TCP > /tmp/offload_check_tcp_shared.bin" &
	local remote_pid=$!
	sleep 1
	local before after
	before=$(dut_counter .rewrite_failures)
	if $DOWNSTREAM_SSH "${DOWNSTREAM_SSH_USER}@${DOWNSTREAM_HOST}" \
		"head -c $TRANSFER_BYTES /dev/urandom > /tmp/offload_check_tcp_shared_sent.bin && timeout 25 nc -q1 $REMOTE_FAKEIP_TARGET $REMOTE_PORT_TCP < /tmp/offload_check_tcp_shared_sent.bin"; then
		wait "$remote_pid" 2>/dev/null || true
		after=$(dut_counter .rewrite_failures)
		local remote_size
		remote_size=$($SSH "${REMOTE_SSH_USER}@${REMOTE_HOST}" "stat -c %s /tmp/offload_check_tcp_shared.bin" 2>/dev/null || echo 0)
		if [[ "$remote_size" != "$TRANSFER_BYTES" ]]; then
			record "$state_label" shared_rewrite_tcp FAIL "expected $TRANSFER_BYTES bytes from $DOWNSTREAM_HOST via the DUT, remote received $remote_size"
			return
		fi
		if [[ -n "$DUT_DIAGNOSTICS_URL" && -n "$before" && -n "$after" && "$after" -gt "$before" ]]; then
			record "$state_label" shared_rewrite_tcp FAIL "$remote_size bytes arrived intact, but the DUT's rewrite_failures counter advanced ($before -> $after) during the transfer"
			return
		fi
		record "$state_label" shared_rewrite_tcp PASS "$remote_size bytes received intact, originated from $DOWNSTREAM_HOST through the DUT"
	else
		record "$state_label" shared_rewrite_tcp FAIL "transfer from $DOWNSTREAM_HOST failed or timed out"
	fi
}

# check_shared_udp_rewrite is check_local_udp_rewrite's shared.data_plane
# counterpart, driven from $DOWNSTREAM_HOST the same way.
check_shared_udp_rewrite() {
	local state_label="$1"
	[[ -z "$DOWNSTREAM_HOST" || -z "$REMOTE_PORT_UDP" ]] && return
	$SSH "${REMOTE_SSH_USER}@${REMOTE_HOST}" \
		"timeout 15 nc -u -l -p $REMOTE_PORT_UDP -w 10 > /tmp/offload_check_udp_shared.bin" &
	local remote_pid=$!
	sleep 1
	$DOWNSTREAM_SSH "${DOWNSTREAM_SSH_USER}@${DOWNSTREAM_HOST}" \
		"head -c 65000 /dev/urandom > /tmp/offload_check_udp_shared_sent.bin && nc -u -q1 -w2 $REMOTE_FAKEIP_TARGET $REMOTE_PORT_UDP < /tmp/offload_check_udp_shared_sent.bin" || true
	wait "$remote_pid" 2>/dev/null || true
	local remote_size
	remote_size=$($SSH "${REMOTE_SSH_USER}@${REMOTE_HOST}" "stat -c %s /tmp/offload_check_udp_shared.bin" 2>/dev/null || echo 0)
	if [[ "$remote_size" != "0" ]]; then
		record "$state_label" shared_rewrite_udp PASS "$remote_size bytes received (UDP is best-effort; a non-zero receipt with matching content, checked separately, is the real pass condition -- see the doc), originated from $DOWNSTREAM_HOST through the DUT"
	else
		record "$state_label" shared_rewrite_udp FAIL "remote received nothing from $DOWNSTREAM_HOST via the DUT"
	fi
}

run_one_combination() {
	local state_label="$1" feature_args="$2"
	echo "=== combination: $state_label ($feature_args) ===" >&2
	set_features "$feature_args"
	if [[ "$COMBINATION_OK" != "1" ]]; then
		record "$state_label" combination_setup UNSUPPORTED "one or more features in this combination could not be applied as requested on $LOCAL_IFACE -- see stderr warnings above; no traffic checks were run under this label"
		return
	fi
	local capture_local="$OUT_DIR/${state_label}.local.pcap"
	local capture_remote_path="/tmp/offload_check_${state_label}.pcap"
	timeout 40 tcpdump -i "$LOCAL_IFACE" -w "$capture_local" >/dev/null 2>&1 &
	local tcpdump_pid=$!
	$SSH "${REMOTE_SSH_USER}@${REMOTE_HOST}" \
		"nohup timeout 40 tcpdump -i any -w $capture_remote_path >/dev/null 2>&1 &" || true
	sleep 1

	check_bypass_passthrough "$state_label"
	check_local_fakeip_icmp "$state_label" 4 "$REMOTE_FAKEIP_TARGET"
	check_shared_fakeip_icmp "$state_label" 4 "$REMOTE_FAKEIP_TARGET"
	if [[ -n "$REMOTE_IPV6" ]]; then
		check_local_fakeip_icmp "$state_label" 6 "$REMOTE_IPV6"
		check_shared_fakeip_icmp "$state_label" 6 "$REMOTE_IPV6"
	fi
	check_local_tcp_rewrite "$state_label"
	check_local_udp_rewrite "$state_label"
	check_shared_tcp_rewrite "$state_label"
	check_shared_udp_rewrite "$state_label"

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
# Every entry names every feature explicitly, including the ones it wants
# left at their normal ("on") value -- see require_complete_combination and
# set_features's own doc comments for why a partial entry is not safe here.
OFFLOAD_MATRIX=(
	"all-on:rx-checksumming=on tx-checksumming=on generic-segmentation-offload=on tcp-segmentation-offload=on generic-receive-offload=on tx-udp-segmentation=on"
	"all-off:rx-checksumming=off tx-checksumming=off generic-segmentation-offload=off tcp-segmentation-offload=off generic-receive-offload=off tx-udp-segmentation=off"
	"tx-checksum-off-only:rx-checksumming=on tx-checksumming=off generic-segmentation-offload=on tcp-segmentation-offload=on generic-receive-offload=on tx-udp-segmentation=on"
	"tso-gso-off-only:rx-checksumming=on tx-checksumming=on generic-segmentation-offload=off tcp-segmentation-offload=off generic-receive-offload=on tx-udp-segmentation=off"
)

for entry in "${OFFLOAD_MATRIX[@]}"; do
	label="${entry%%:*}"
	args="${entry#*:}"
	require_complete_combination "$label" "$args"
done

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
