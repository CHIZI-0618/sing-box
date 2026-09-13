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
# TEST_ROLE picks which of local.data_plane/shared.data_plane this run
# checks: "local", "shared", or "both" (the default). A second independent
# review found this run_one_combination previously ran the local checks
# unconditionally regardless of TEST_ROLE's absence entirely -- a DUT
# deliberately configured with only shared.data_plane enabled (exactly the
# deployment this whole engagement has treated as a first-class
# configuration) had no local responder for the local checks to reach, so
# they would fail and take the whole run down with them even when
# shared.data_plane's own checks passed cleanly. Every check the selected
# role excludes is recorded NOT_TESTED, not silently omitted.
: "${TEST_ROLE:=both}"
case "$TEST_ROLE" in
local | shared | both) ;;
*)
	echo "TEST_ROLE must be one of: local, shared, both (got '$TEST_ROLE')" >&2
	exit 1
	;;
esac
if [[ "$TEST_ROLE" != "local" && -z "$DOWNSTREAM_HOST" ]]; then
	echo "TEST_ROLE=$TEST_ROLE requires DOWNSTREAM_HOST to be set (shared.data_plane can only be verified from a real downstream client)" >&2
	exit 1
fi

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
#
# actual_feature_state's own call site here is guarded the same way as
# every evidence read elsewhere in this file: a comprehensive sweep,
# prompted by a sixth independent review's finding that this same
# unguarded-command-substitution-under-set-e shape kept recurring one site
# at a time across five prior rounds, found this local `ethtool -k | awk`
# read was the last remaining site of that shape -- a failed or driver-
# confused ethtool read here would otherwise abort the whole script rather
# than simply marking this one combination unreliable and moving on.
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
		if ! actual=$(actual_feature_state "$feature"); then
			actual=""
		fi
		if [[ -z "$actual" ]]; then
			echo "warning: could not read back the state of $feature on $LOCAL_IFACE after setting it (the ethtool read itself failed) -- treating this combination as not confirmed" >&2
			COMBINATION_OK=0
			continue
		fi
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

# check_local_fakeip_icmp's packet-loss parse is guarded the same way as
# every other evidence read in this file -- the same comprehensive sweep
# that fixed set_features's ethtool read found `grep -oP` here exits
# non-zero whenever ping's output does not contain the expected "N% packet
# loss" phrase at all (not merely an unexpected number), which a bare
# assignment would have let abort the whole script under set -e instead of
# recording a distinct, explicit "could not parse" failure.
check_local_fakeip_icmp() {
	local state_label="$1" family="$2" target="$3"
	local ping_bin=ping
	[[ "$family" == "6" ]] && ping_bin=ping6
	local out
	if out=$($ping_bin -c "$PING_COUNT" -q "$target" 2>&1); then
		local loss
		if ! loss=$(echo "$out" | grep -oP '\d+(?=% packet loss)'); then
			loss=""
		fi
		if [[ ! "$loss" =~ ^[0-9]+$ ]]; then
			record "$state_label" "local_fakeip_icmp_v${family}" FAIL "ping succeeded but its packet-loss percentage could not be parsed from the output -- evidence-read error, not a content judgment (output: $out)"
			return
		fi
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

# check_local_tcp_rewrite (and every other hash-comparison check in this
# file: check_local_udp_rewrite, check_shared_tcp_rewrite,
# check_shared_udp_rewrite) guards each `_hash=$($SSH ...)` /
# `_hash=$($DOWNSTREAM_SSH ...)` retrieval with an explicit
# `if ! x=$(...); then x=""; fi` and then validates the result as a
# 64-character lowercase hex SHA-256 digest -- a fifth independent review
# found these assignments were still bare command substitutions under this
# script's own `set -euo pipefail` (the same class of bug §15/round-4 fixed
# for the UDP receipt-size read, at six more sites this file's hash
# preparation and retrieval never got the same treatment): a failed SSH
# call at any of them aborted the whole script instead of recording a
# structured FAIL. A successful-but-malformed result (empty, truncated, or
# not hex) is rejected the same way a failed call is, and is reported
# explicitly as an evidence-read error rather than folded into a "content
# mismatch" verdict, which would otherwise blame corruption for what is
# actually an inability to read the evidence at all. The same guard also
# covers this function's (and check_local_udp_rewrite's) *local*
# sent_hash computation over a file the script just wrote itself: lower
# likelihood than a remote SSH call, but a comprehensive sweep across the
# whole file found it has the identical unguarded shape, and it is no less
# capable of aborting the script if sha256sum or cut are ever unavailable.
check_local_tcp_rewrite() {
	local state_label="$1"
	[[ -z "$REMOTE_PORT_TCP" ]] && return
	$SSH "${REMOTE_SSH_USER}@${REMOTE_HOST}" \
		"timeout 30 nc -l -p $REMOTE_PORT_TCP > /tmp/offload_check_tcp.bin" &
	local remote_pid=$!
	sleep 1
	head -c "$TRANSFER_BYTES" /dev/urandom > "$OUT_DIR/tcp_sent.bin"
	local sent_hash
	if ! sent_hash=$(sha256sum "$OUT_DIR/tcp_sent.bin" | cut -d' ' -f1); then
		sent_hash=""
	fi
	if [[ ! "$sent_hash" =~ ^[0-9a-f]{64}$ ]]; then
		record "$state_label" local_shared_rewrite_tcp FAIL "could not compute a valid SHA-256 of the payload this script itself just wrote to $OUT_DIR/tcp_sent.bin -- evidence-preparation error, not a content judgment"
		wait "$remote_pid" 2>/dev/null || true
		return
	fi
	if ! timeout 25 nc -q1 "$REMOTE_FAKEIP_TARGET" "$REMOTE_PORT_TCP" < "$OUT_DIR/tcp_sent.bin"; then
		record "$state_label" local_shared_rewrite_tcp FAIL "the local nc transfer command itself failed or timed out"
		wait "$remote_pid" 2>/dev/null || true
		return
	fi
	wait "$remote_pid" 2>/dev/null || true
	local remote_hash
	if ! remote_hash=$($SSH "${REMOTE_SSH_USER}@${REMOTE_HOST}" "sha256sum /tmp/offload_check_tcp.bin 2>/dev/null | cut -d' ' -f1"); then
		remote_hash=""
	fi
	if [[ ! "$remote_hash" =~ ^[0-9a-f]{64}$ ]]; then
		record "$state_label" local_shared_rewrite_tcp FAIL "could not read a valid SHA-256 from the remote (remote received no data at all, sha256sum is unavailable there, or the SSH call itself failed) -- evidence-read error, not a content judgment"
		return
	fi
	if [[ "$remote_hash" == "$sent_hash" ]]; then
		record "$state_label" local_shared_rewrite_tcp PASS "SHA-256 of received data matches sent data ($TRANSFER_BYTES bytes, $sent_hash), originated from the DUT itself"
	else
		record "$state_label" local_shared_rewrite_tcp FAIL "content mismatch: sent SHA-256 $sent_hash, remote SHA-256 $remote_hash -- corrupted in transit, not merely a byte-count difference"
	fi
}

# check_local_udp_rewrite compares SHA-256 of the sent and received datagram
# rather than treating any non-zero receipt as sufficient -- a second
# independent review found the earlier byte-count-only check would record
# PASS even for truncated or corrupted data, and even when the local send
# command itself had already failed, as long as *something* non-zero showed
# up in the remote file. UDP is genuinely best-effort, so total loss (an
# empty remote file) is retried up to three times before being recorded as
# a failure; a datagram that *did* arrive but does not match what was sent
# is recorded as an immediate failure on its own attempt, never retried
# away, since that is evidence of corruption, not merely of loss.
#
# A third independent review found that a nonzero exit from the send command
# was itself being treated as proof of total loss: the receipt was never
# inspected on that attempt at all, it was just retried. But a sender or its
# connection can fail *after* already transmitting some or all of a
# datagram, so a nonzero send exit does not establish that nothing arrived --
# an attempt whose send command failed yet whose receiver actually got a
# nonempty, non-matching datagram is real evidence of corruption that a
# later, coincidentally successful retry must not be allowed to hide behind
# a PASS. The send command's exit status is now kept only to explain a
# genuinely empty receipt (which is what the loss-retry exists for); it is
# never used by itself to skip inspecting what the receiver actually got.
# Unreadable receiver evidence (the remote stat command itself failing, or
# succeeding but not printing a plain byte count) is never treated as an
# established empty receipt and never permitted to retry as if it were one
# -- a fourth independent review found the bare `remote_size=$($SSH ...)`
# assignment was itself unguarded under this script's `set -euo pipefail`,
# so a nonzero exit from that SSH/stat call (a dropped connection, a
# transient remote error) aborted the whole script before the emptiness
# check downstream ever ran, silencing the rest of the offload matrix and
# the final summary instead of recording a structured outcome for this
# attempt. Retrieval is now guarded explicitly and its result validated as
# a plain nonnegative integer; anything else -- a failed SSH call or
# malformed output alike -- is recorded as an immediate FAIL naming the
# evidence-read error, never silently retried as a fresh transfer attempt,
# since only a successfully read, confirmed-zero size is genuine evidence
# of total loss.
check_local_udp_rewrite() {
	local state_label="$1"
	[[ -z "$REMOTE_PORT_UDP" ]] && return
	head -c 65000 /dev/urandom > "$OUT_DIR/udp_sent.bin"
	local sent_hash
	if ! sent_hash=$(sha256sum "$OUT_DIR/udp_sent.bin" | cut -d' ' -f1); then
		sent_hash=""
	fi
	if [[ ! "$sent_hash" =~ ^[0-9a-f]{64}$ ]]; then
		record "$state_label" local_shared_rewrite_udp FAIL "could not compute a valid SHA-256 of the payload this script itself just wrote to $OUT_DIR/udp_sent.bin -- evidence-preparation error, not a content judgment"
		return
	fi
	local attempt send_status remote_size remote_hash
	for attempt in 1 2 3; do
		$SSH "${REMOTE_SSH_USER}@${REMOTE_HOST}" \
			"timeout 15 nc -u -l -p $REMOTE_PORT_UDP -w 10 > /tmp/offload_check_udp.bin" &
		local remote_pid=$!
		sleep 1
		send_status=0
		nc -u -q1 -w2 "$REMOTE_FAKEIP_TARGET" "$REMOTE_PORT_UDP" < "$OUT_DIR/udp_sent.bin" || send_status=$?
		wait "$remote_pid" 2>/dev/null || true
		if ! remote_size=$($SSH "${REMOTE_SSH_USER}@${REMOTE_HOST}" "stat -c %s /tmp/offload_check_udp.bin" 2>/dev/null); then
			remote_size=""
		fi
		if [[ ! "$remote_size" =~ ^[0-9]+$ ]]; then
			record "$state_label" local_shared_rewrite_udp FAIL "could not read the receiver's file size on attempt $attempt/3 (local send command exit=$send_status; stat result '$remote_size' is not a valid byte count) -- unreadable or invalid evidence is never treated as a confirmed empty receipt, so this attempt is not eligible for a fresh transfer retry"
			return
		fi
		if [[ "$remote_size" == "0" ]]; then
			if [[ "$send_status" -ne 0 ]]; then
				echo "warning: no data received on attempt $attempt/3, consistent with the local send command's own failure (exit=$send_status); retrying" >&2
			else
				echo "warning: no data received on attempt $attempt/3 (UDP is best-effort); retrying" >&2
			fi
			continue
		fi
		if ! remote_hash=$($SSH "${REMOTE_SSH_USER}@${REMOTE_HOST}" "sha256sum /tmp/offload_check_udp.bin 2>/dev/null | cut -d' ' -f1"); then
			remote_hash=""
		fi
		if [[ ! "$remote_hash" =~ ^[0-9a-f]{64}$ ]]; then
			record "$state_label" local_shared_rewrite_udp FAIL "could not read a valid SHA-256 from the remote on attempt $attempt/3 (sha256sum is unavailable there, or the SSH call itself failed) -- evidence-read error, not a content judgment"
			return
		fi
		if [[ "$remote_hash" == "$sent_hash" ]]; then
			record "$state_label" local_shared_rewrite_udp PASS "SHA-256 of received datagram matches sent data on attempt $attempt/3 ($sent_hash), originated from the DUT itself (local send command exit=$send_status)"
			return
		fi
		record "$state_label" local_shared_rewrite_udp FAIL "content mismatch on attempt $attempt (local send command exit=$send_status): sent SHA-256 $sent_hash, remote SHA-256 $remote_hash -- corrupted in transit, not a total-loss condition eligible for retry"
		return
	done
	record "$state_label" local_shared_rewrite_udp FAIL "no data received after 3 attempts -- UDP is best-effort, but total loss across 3 attempts on a real link during an offload check is itself worth investigating, not accepted silently"
}

# check_shared_fakeip_icmp is check_local_fakeip_icmp's shared.data_plane
# counterpart: the ping is originated from $DOWNSTREAM_HOST over ssh, never
# from the DUT, since shared.data_plane only ever sees traffic arriving from
# a real downstream client -- a DUT-originated ping proves nothing about it.
# When DUT_DIAGNOSTICS_URL is set, this also requires the DUT's own
# fakeip_icmp_replies counter to have actually advanced, which is real
# evidence the packet was processed by this inbound's eBPF code specifically
# and not, say, answered by some unrelated device on the same segment.
#
# A sixth independent review found dut_counter's own two call sites here
# were still bare command substitutions under this script's `set -euo
# pipefail`: dut_counter's internal `curl | jq` pipeline can exit nonzero
# under `pipefail` when DUT_DIAGNOSTICS_URL is configured but the DUT's
# diagnostics endpoint is unreachable, which aborted the whole script
# instead of recording a structured outcome -- disclosed but left unfixed
# after the fifth review, since that review had named a different six
# sites. Both reads are now guarded the same way as every other evidence
# read in this file, and their results validated as plain nonnegative
# integers rather than merely checked for emptiness: a read that fails, or
# succeeds with a non-numeric result, is an immediate, explicit FAIL when
# DUT_DIAGNOSTICS_URL is configured -- it is never silently treated the
# same as DUT_DIAGNOSTICS_URL being unset, which would let a configured but
# broken diagnostics endpoint quietly downgrade this check to the weaker,
# opt-out mode instead of reporting that the stronger mode it was
# configured for could not actually run. Its packet-loss parse below is
# guarded the same way, for the same reason as check_local_fakeip_icmp's
# own parse (see that function's comment): a comprehensive sweep across
# the whole file, prompted by how many rounds it took independent review
# to find every prior instance of this same shape one at a time, found
# this site too.
check_shared_fakeip_icmp() {
	local state_label="$1" family="$2" target="$3"
	[[ -z "$DOWNSTREAM_HOST" ]] && return
	local ping_bin=ping
	[[ "$family" == "6" ]] && ping_bin=ping6
	local before after out
	if ! before=$(dut_counter .fakeip_icmp_replies); then
		before=""
	fi
	if [[ -n "$DUT_DIAGNOSTICS_URL" && ! "$before" =~ ^[0-9]+$ ]]; then
		record "$state_label" "shared_fakeip_icmp_v${family}" FAIL "DUT_DIAGNOSTICS_URL is configured but the 'before' fakeip_icmp_replies counter could not be read -- evidence-read error, not a content judgment"
		return
	fi
	if out=$($DOWNSTREAM_SSH "${DOWNSTREAM_SSH_USER}@${DOWNSTREAM_HOST}" "$ping_bin -c $PING_COUNT -q $target" 2>&1); then
		if ! after=$(dut_counter .fakeip_icmp_replies); then
			after=""
		fi
		if [[ -n "$DUT_DIAGNOSTICS_URL" && ! "$after" =~ ^[0-9]+$ ]]; then
			record "$state_label" "shared_fakeip_icmp_v${family}" FAIL "DUT_DIAGNOSTICS_URL is configured but the 'after' fakeip_icmp_replies counter could not be read -- evidence-read error, not a content judgment"
			return
		fi
		local loss
		if ! loss=$(echo "$out" | grep -oP '\d+(?=% packet loss)'); then
			loss=""
		fi
		if [[ ! "$loss" =~ ^[0-9]+$ ]]; then
			record "$state_label" "shared_fakeip_icmp_v${family}" FAIL "ping from $DOWNSTREAM_HOST succeeded but its packet-loss percentage could not be parsed from the output -- evidence-read error, not a content judgment (output: $out)"
			return
		fi
		if [[ "$loss" != "0" ]]; then
			record "$state_label" "shared_fakeip_icmp_v${family}" FAIL "${loss}% loss over $PING_COUNT pings to $target from $DOWNSTREAM_HOST"
			return
		fi
		if [[ -n "$DUT_DIAGNOSTICS_URL" ]]; then
			if [[ "$after" -le "$before" ]]; then
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
#
# Its two dut_counter reads are guarded and validated the same way, and for
# the same reason, as check_shared_fakeip_icmp's own two reads (see that
# function's comment) -- a sixth independent review found both were still
# bare, unguarded assignments, and that the final comparison below required
# both to be non-empty before ever treating a configured-but-unreadable
# counter as anything other than a silent PASS, exactly the "configured
# diagnostics quietly downgrading to opt-out behavior" defect
# check_shared_fakeip_icmp had to avoid too. Both reads now fail fast,
# immediately after being taken, whenever DUT_DIAGNOSTICS_URL is configured
# but the read did not produce a valid nonnegative integer -- consistent
# with how every other evidence read in this function (sent_hash,
# remote_hash) already fails fast rather than deferring the judgment to a
# later comparison that could silently no-op on invalid input.
check_shared_tcp_rewrite() {
	local state_label="$1"
	[[ -z "$DOWNSTREAM_HOST" || -z "$REMOTE_PORT_TCP" ]] && return
	$SSH "${REMOTE_SSH_USER}@${REMOTE_HOST}" \
		"timeout 30 nc -l -p $REMOTE_PORT_TCP > /tmp/offload_check_tcp_shared.bin" &
	local remote_pid=$!
	sleep 1
	local before after sent_hash
	if ! before=$(dut_counter .rewrite_failures); then
		before=""
	fi
	if [[ -n "$DUT_DIAGNOSTICS_URL" && ! "$before" =~ ^[0-9]+$ ]]; then
		record "$state_label" shared_rewrite_tcp FAIL "DUT_DIAGNOSTICS_URL is configured but the 'before' rewrite_failures counter could not be read -- evidence-read error, not a content judgment"
		wait "$remote_pid" 2>/dev/null || true
		return
	fi
	if ! sent_hash=$($DOWNSTREAM_SSH "${DOWNSTREAM_SSH_USER}@${DOWNSTREAM_HOST}" \
		"head -c $TRANSFER_BYTES /dev/urandom > /tmp/offload_check_tcp_shared_sent.bin && sha256sum /tmp/offload_check_tcp_shared_sent.bin | cut -d' ' -f1"); then
		sent_hash=""
	fi
	if [[ ! "$sent_hash" =~ ^[0-9a-f]{64}$ ]]; then
		record "$state_label" shared_rewrite_tcp FAIL "could not prepare a valid send payload/SHA-256 on $DOWNSTREAM_HOST (the SSH call itself may have failed) -- evidence-read error, not a content judgment"
		wait "$remote_pid" 2>/dev/null || true
		return
	fi
	if ! $DOWNSTREAM_SSH "${DOWNSTREAM_SSH_USER}@${DOWNSTREAM_HOST}" \
		"timeout 25 nc -q1 $REMOTE_FAKEIP_TARGET $REMOTE_PORT_TCP < /tmp/offload_check_tcp_shared_sent.bin"; then
		record "$state_label" shared_rewrite_tcp FAIL "the transfer command on $DOWNSTREAM_HOST itself failed or timed out"
		wait "$remote_pid" 2>/dev/null || true
		return
	fi
	wait "$remote_pid" 2>/dev/null || true
	if ! after=$(dut_counter .rewrite_failures); then
		after=""
	fi
	if [[ -n "$DUT_DIAGNOSTICS_URL" && ! "$after" =~ ^[0-9]+$ ]]; then
		record "$state_label" shared_rewrite_tcp FAIL "DUT_DIAGNOSTICS_URL is configured but the 'after' rewrite_failures counter could not be read -- evidence-read error, not a content judgment"
		return
	fi
	local remote_hash
	if ! remote_hash=$($SSH "${REMOTE_SSH_USER}@${REMOTE_HOST}" "sha256sum /tmp/offload_check_tcp_shared.bin 2>/dev/null | cut -d' ' -f1"); then
		remote_hash=""
	fi
	if [[ ! "$remote_hash" =~ ^[0-9a-f]{64}$ ]]; then
		record "$state_label" shared_rewrite_tcp FAIL "could not read a valid SHA-256 from the remote (remote received no data at all from $DOWNSTREAM_HOST via the DUT, sha256sum is unavailable there, or the SSH call itself failed) -- evidence-read error, not a content judgment"
		return
	fi
	if [[ "$remote_hash" != "$sent_hash" ]]; then
		record "$state_label" shared_rewrite_tcp FAIL "content mismatch: sent SHA-256 $sent_hash, remote SHA-256 $remote_hash -- corrupted in transit, not merely a byte-count difference"
		return
	fi
	if [[ -n "$DUT_DIAGNOSTICS_URL" && "$after" -gt "$before" ]]; then
		record "$state_label" shared_rewrite_tcp FAIL "content arrived intact (SHA-256 $remote_hash), but the DUT's rewrite_failures counter advanced ($before -> $after) during the transfer"
		return
	fi
	record "$state_label" shared_rewrite_tcp PASS "SHA-256 of received data matches sent data ($sent_hash), originated from $DOWNSTREAM_HOST through the DUT"
}

# check_shared_udp_rewrite is check_local_udp_rewrite's shared.data_plane
# counterpart, driven from $DOWNSTREAM_HOST the same way, with the same
# SHA-256-comparison, retry-on-total-loss-only, and send-status-never-skips-
# the-receipt-check semantics (see check_local_udp_rewrite's own comment).
check_shared_udp_rewrite() {
	local state_label="$1"
	[[ -z "$DOWNSTREAM_HOST" || -z "$REMOTE_PORT_UDP" ]] && return
	local sent_hash
	if ! sent_hash=$($DOWNSTREAM_SSH "${DOWNSTREAM_SSH_USER}@${DOWNSTREAM_HOST}" \
		"head -c 65000 /dev/urandom > /tmp/offload_check_udp_shared_sent.bin && sha256sum /tmp/offload_check_udp_shared_sent.bin | cut -d' ' -f1"); then
		sent_hash=""
	fi
	if [[ ! "$sent_hash" =~ ^[0-9a-f]{64}$ ]]; then
		record "$state_label" shared_rewrite_udp FAIL "could not prepare a valid send payload/SHA-256 on $DOWNSTREAM_HOST (the SSH call itself may have failed) -- evidence-read error, not a content judgment"
		return
	fi
	local attempt send_status remote_size remote_hash
	for attempt in 1 2 3; do
		$SSH "${REMOTE_SSH_USER}@${REMOTE_HOST}" \
			"timeout 15 nc -u -l -p $REMOTE_PORT_UDP -w 10 > /tmp/offload_check_udp_shared.bin" &
		local remote_pid=$!
		sleep 1
		send_status=0
		$DOWNSTREAM_SSH "${DOWNSTREAM_SSH_USER}@${DOWNSTREAM_HOST}" \
			"nc -u -q1 -w2 $REMOTE_FAKEIP_TARGET $REMOTE_PORT_UDP < /tmp/offload_check_udp_shared_sent.bin" || send_status=$?
		wait "$remote_pid" 2>/dev/null || true
		if ! remote_size=$($SSH "${REMOTE_SSH_USER}@${REMOTE_HOST}" "stat -c %s /tmp/offload_check_udp_shared.bin" 2>/dev/null); then
			remote_size=""
		fi
		if [[ ! "$remote_size" =~ ^[0-9]+$ ]]; then
			record "$state_label" shared_rewrite_udp FAIL "could not read the receiver's file size on attempt $attempt/3 (send command on $DOWNSTREAM_HOST exit=$send_status; stat result '$remote_size' is not a valid byte count) -- unreadable or invalid evidence is never treated as a confirmed empty receipt, so this attempt is not eligible for a fresh transfer retry"
			return
		fi
		if [[ "$remote_size" == "0" ]]; then
			if [[ "$send_status" -ne 0 ]]; then
				echo "warning: no data received on attempt $attempt/3, consistent with the send command on $DOWNSTREAM_HOST failing (exit=$send_status); retrying" >&2
			else
				echo "warning: no data received on attempt $attempt/3 (UDP is best-effort); retrying" >&2
			fi
			continue
		fi
		if ! remote_hash=$($SSH "${REMOTE_SSH_USER}@${REMOTE_HOST}" "sha256sum /tmp/offload_check_udp_shared.bin 2>/dev/null | cut -d' ' -f1"); then
			remote_hash=""
		fi
		if [[ ! "$remote_hash" =~ ^[0-9a-f]{64}$ ]]; then
			record "$state_label" shared_rewrite_udp FAIL "could not read a valid SHA-256 from the remote on attempt $attempt/3 (sha256sum is unavailable there, or the SSH call itself failed) -- evidence-read error, not a content judgment"
			return
		fi
		if [[ "$remote_hash" == "$sent_hash" ]]; then
			record "$state_label" shared_rewrite_udp PASS "SHA-256 of received datagram matches sent data on attempt $attempt/3 ($sent_hash), originated from $DOWNSTREAM_HOST through the DUT (send command exit=$send_status)"
			return
		fi
		record "$state_label" shared_rewrite_udp FAIL "content mismatch on attempt $attempt (send command on $DOWNSTREAM_HOST exit=$send_status): sent SHA-256 $sent_hash, remote SHA-256 $remote_hash -- corrupted in transit, not a total-loss condition eligible for retry"
		return
	done
	record "$state_label" shared_rewrite_udp FAIL "no data received from $DOWNSTREAM_HOST via the DUT after 3 attempts -- UDP is best-effort, but total loss across 3 attempts on a real link during an offload check is itself worth investigating, not accepted silently"
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

	if [[ "$TEST_ROLE" == "local" || "$TEST_ROLE" == "both" ]]; then
		check_local_fakeip_icmp "$state_label" 4 "$REMOTE_FAKEIP_TARGET"
		if [[ -n "$REMOTE_IPV6" ]]; then
			check_local_fakeip_icmp "$state_label" 6 "$REMOTE_IPV6"
		fi
		check_local_tcp_rewrite "$state_label"
		check_local_udp_rewrite "$state_label"
	else
		record "$state_label" local_data_plane NOT_TESTED "TEST_ROLE=$TEST_ROLE excludes local.data_plane; its checks were deliberately not run for this combination"
	fi

	if [[ "$TEST_ROLE" == "shared" || "$TEST_ROLE" == "both" ]]; then
		check_shared_fakeip_icmp "$state_label" 4 "$REMOTE_FAKEIP_TARGET"
		if [[ -n "$REMOTE_IPV6" ]]; then
			check_shared_fakeip_icmp "$state_label" 6 "$REMOTE_IPV6"
		fi
		check_shared_tcp_rewrite "$state_label"
		check_shared_udp_rewrite "$state_label"
	else
		record "$state_label" shared_data_plane NOT_TESTED "TEST_ROLE=$TEST_ROLE excludes shared.data_plane; its checks were deliberately not run for this combination"
	fi

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

# A second independent review found that summing up to a bare "grep -q
# FAIL" check meant a run in which every combination was UNSUPPORTED (no
# ethtool support on this NIC, or the driver refusing every requested
# state) still printed "all recorded checks PASSed" and exited 0 -- there
# was no FAIL line to find, but nothing had actually been verified either.
# This counts every outcome category from the report's own status column
# (not a free-text search, which a detail message could coincidentally
# match) and distinguishes a genuine, unambiguous pass from one that
# verified nothing, or verified less than the full matrix, with a
# different exit status for each so a caller (or a human) cannot mistake
# one for the other from the exit code alone.
#
# This read-back of $REPORT is guarded explicitly, unlike every other
# guard in this file: rather than defaulting a failed read to an empty/zero
# count (which would misreport a report that became unreadable at the very
# last step as INCONCLUSIVE -- "nothing passed" -- when the real problem is
# that the whole run's evidence could not be read back at all), an
# unreadable report here is its own distinct, unambiguous fatal condition
# with its own exit code, never confused with any of the four outcomes
# that assume $REPORT was read successfully.
#
# A seventh independent review found that the `[[ -r "$REPORT" ]]` test
# above only ever caught a report already missing or inaccessible at that
# instant -- it said nothing about the four `awk | wc -l` pipelines that
# actually read it a moment later, which were themselves still bare,
# unguarded command substitutions. A file confirmed readable can still fail
# to be read moments later (deleted out from under the script, a broken
# awk/wc, a later I/O error), and that failure propagated straight out of
# the script as a raw, undocumented exit code instead of the FATAL/exit 4
# this section exists to guarantee. The four separate reads are now one
# single guarded awk pass computing every count from the same read of the
# file, so every category is guaranteed consistent with the others, its
# result is validated as four plain integers before being trusted, and any
# failure at any stage -- the read itself, or a malformed result -- reaches
# the same FATAL/exit 4 the readability check immediately below already
# establishes for the plain missing/inaccessible case.
if [[ ! -r "$REPORT" ]]; then
	echo "FATAL: $REPORT is not readable -- cannot compute the final summary from a report this run itself was writing to throughout; this is not the same as INCONCLUSIVE (which means the report was read fine but nothing in it passed)" >&2
	exit 4
fi
if ! SUMMARY_COUNTS=$(awk -F'\t' '
	NR>1 {
		if ($3=="PASS") pass++
		else if ($3=="FAIL") fail++
		else if ($3=="UNSUPPORTED") unsupported++
		else if ($3=="NOT_TESTED") not_tested++
	}
	END { printf "%d %d %d %d", pass+0, fail+0, unsupported+0, not_tested+0 }
' "$REPORT"); then
	echo "FATAL: could not compute the final summary from $REPORT -- the statistics read itself failed even though the report was confirmed readable a moment earlier" >&2
	exit 4
fi
if [[ ! "$SUMMARY_COUNTS" =~ ^[0-9]+\ [0-9]+\ [0-9]+\ [0-9]+$ ]]; then
	echo "FATAL: the final summary computation produced an unexpected result ('$SUMMARY_COUNTS') from $REPORT -- not trusting a malformed count" >&2
	exit 4
fi
read -r PASS_COUNT FAIL_COUNT UNSUPPORTED_COUNT NOT_TESTED_COUNT <<< "$SUMMARY_COUNTS"

echo "summary: $PASS_COUNT PASS, $FAIL_COUNT FAIL, $UNSUPPORTED_COUNT UNSUPPORTED, $NOT_TESTED_COUNT NOT_TESTED (TEST_ROLE=$TEST_ROLE)" >&2

if [[ "$FAIL_COUNT" -gt 0 ]]; then
	echo "FAIL: at least one check failed -- see $REPORT" >&2
	exit 1
fi
if [[ "$PASS_COUNT" -eq 0 ]]; then
	echo "INCONCLUSIVE: no check actually passed in this run -- this environment verified nothing; do not read a lack of FAIL as evidence the eBPF rewrite is correct" >&2
	exit 2
fi
if [[ "$UNSUPPORTED_COUNT" -gt 0 ]]; then
	echo "PARTIAL: $PASS_COUNT check(s) passed, but $UNSUPPORTED_COUNT combination(s) were UNSUPPORTED on this NIC/driver and never verified -- see $REPORT for exactly which" >&2
	exit 3
fi
echo "all recorded checks PASSed ($PASS_COUNT check(s); $NOT_TESTED_COUNT deliberately excluded by TEST_ROLE=$TEST_ROLE)" >&2
