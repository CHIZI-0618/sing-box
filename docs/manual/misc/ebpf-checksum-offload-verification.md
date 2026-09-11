# eBPF checksum/offload verification

This is the real-hardware verification procedure for item 13 of the eBPF
inbound reliability work: whether the packets this inbound's TC programs
rewrite in place (bypass_rule_set CIDR matching, `shared.data_plane:
packet_rewrite`, and `fakeip_icmp: reply`'s incremental ICMP checksum update)
remain correct once a real NIC's checksum offload, GRO, GSO, or TSO is
involved. Every other test in this codebase runs against veth pairs in
network namespaces, which have no hardware offload path at all — a software
loopback always computes checksums honestly regardless of what NIC feature
flags claim, so those tests cannot catch a rewrite that only an offloading
NIC's firmware or driver would mishandle.

**This procedure has not been run.** No environment with two real Linux
hosts joined by a real NIC was available while this round of work was done.
It ships as a documented, ready-to-run Go tool and procedure for whoever has
that hardware, not as a claim that hardware behavior has been checked.

## Why a real NIC, specifically

A veth pair's "hardware" checksum offload flags are advisory only — the
kernel's software networking stack always computes a correct checksum
regardless of what `ethtool -k veth0` reports, because there is no real
device firmware in the path to skip that work. A cloud VM's virtio-net
interface behaves the same way for the same reason: virtio-net's "hardware"
checksum offload is itself implemented in the hypervisor's software network
stack. Only a physical NIC (or a SR-IOV/passthrough virtual function backed
by one) with a real onboard checksum/segmentation engine exercises the code
path this procedure is checking: an eBPF program changing header bytes
in a packet the NIC's own silicon or firmware, not the kernel, will finish
checksumming before it leaves the machine.

## Roles

An earlier version of this procedure drove every check from the DUT itself,
which an independent review pointed out cannot actually verify
`shared.data_plane` at all: traffic the DUT originates only ever exercises
`local.data_plane`'s TC **egress** classifier, never `shared.data_plane`'s
**ingress** one, which only ever sees traffic arriving from a real
downstream client. This procedure now names three roles explicitly:

- **DUT**: the host running the eBPF inbound under test, attached to
  `$LOCAL_IFACE`. The verification tool itself runs here.
- **`$REMOTE_HOST`**: a real, non-FakeIP destination the DUT can reach,
  reachable over ssh. Used for the `bypass_rule_set` control case (a flow
  it is expected to leave completely untouched) and, when checking
  `local.data_plane`, as what the DUT itself talks to through its own local
  egress path.
- **`$DOWNSTREAM_HOST`** (only needed to check `shared.data_plane`): a
  separate host reachable from the DUT's shared-facing interface, standing
  in for a real LAN client. Every `shared.data_plane` check is driven from
  this host toward the FakeIP target, over ssh — never from the DUT, which
  would silently re-test `local.data_plane`'s own code path instead.

If both `local.data_plane` and `shared.data_plane` are enabled on the DUT at
once, a downstream-originated reply passing is not, on its own, proof that
`shared.data_plane` specifically answered it — see `$DUT_DIAGNOSTICS_URL`
below for the one thing that can actually distinguish this, and its own
limits. Where that ambiguity matters, run the DUT with only the role under
test enabled.

An earlier version of this script always ran both the DUT-originated
(`local.data_plane`) checks and the `$DOWNSTREAM_HOST`-originated
(`shared.data_plane`) checks in every run, regardless of which of the two
this documentation told you to disable on the DUT — a DUT deliberately
configured with only `shared.data_plane` enabled (a legitimate, first-class
deployment) had no local responder for the unconditional local checks to
reach, so those checks would fail and take the whole run down even though
`shared.data_plane` itself was working correctly. `$TEST_ROLE` (see below)
now selects which of the two actually runs, so a shared-only DUT can be
verified cleanly without also enabling `local.data_plane` just to satisfy
this script.

## Required environment

- Two real Linux hosts (DUT and `$REMOTE_HOST`) connected by a real NIC on
  each end — a physical Ethernet link, or a datacenter NIC configured for
  SR-IOV passthrough into a VM. Confirm with `ethtool -i <iface>` that the
  driver is a real hardware driver (`ixgbe`, `i40e`, `mlx5_core`, `r8169`,
  `igc`, ... — not `veth`, `virtio_net`, or `vmxnet3`). A third host,
  `$DOWNSTREAM_HOST`, reachable from the DUT's shared-facing interface, is
  additionally required to check `shared.data_plane` at all.
- Root on every host involved, and non-interactive (key-based) SSH from the
  DUT to `$REMOTE_HOST` and, if used, to `$DOWNSTREAM_HOST`.
- Go, `ethtool`, `tcpdump`, and `nc` (netcat) on the DUT; `tcpdump` and `nc`
  on `$REMOTE_HOST`; and `nc` on `$DOWNSTREAM_HOST` when shared checks run.
- sing-box built with the eBPF inbound already running on the DUT, attached
  to the NIC named `$LOCAL_IFACE`, with a configuration that exercises the
  paths this procedure checks:
  - `fakeip_icmp: reply` enabled, with a FakeIP prefix that matches
    `$FAKEIP_PREFIX` below.
  - `shared.data_plane: packet_rewrite` enabled if `$REMOTE_PORT_TCP` /
    `$REMOTE_PORT_UDP` are set together with `$DOWNSTREAM_HOST` (to exercise
    the NAT/flow-rewrite path from a real downstream client).
  - Route `$REMOTE_HOST` through this inbound so `bypass_rule_set` (if
    configured) has a real matched flow to evaluate.
  - If checking `shared.data_plane`, optionally enable the Clash API server
    and point `$DUT_DIAGNOSTICS_URL` at its `/ebpf` route (see
    [eBPF inbound troubleshooting](/manual/misc/ebpf-troubleshooting/)) so
    the script can confirm the DUT's own counters actually advanced, not
    just that some reply arrived.

## Running it

```sh
go build -o /tmp/sing-box-checksumoffload ./common/ebpf/testing/checksumoffload

sudo LOCAL_IFACE=eth0 \
    REMOTE_HOST=192.0.2.10 \
    REMOTE_SSH_USER=root \
    DOWNSTREAM_HOST=192.0.2.20 \
    DOWNSTREAM_SSH_USER=root \
    DUT_DIAGNOSTICS_URL=http://127.0.0.1:9090/ebpf \
    FAKEIP_PREFIX=198.18.0.0/15 \
    REMOTE_FAKEIP_TARGET=198.18.0.1 \
    REMOTE_IPV6=fdfe:dcba:9876::1 \
    REMOTE_PORT_TCP=15000 \
    REMOTE_PORT_UDP=15001 \
    TEST_ROLE=both \
    /tmp/sing-box-checksumoffload
```

Only `LOCAL_IFACE`, `REMOTE_HOST`, `FAKEIP_PREFIX`, and
`REMOTE_FAKEIP_TARGET` are required. `$TEST_ROLE` picks which data plane this
run actually checks and defaults to `both`:

- `local` — only `local.data_plane`'s checks run, driven from the DUT
  itself. `$DOWNSTREAM_HOST` is not required.
- `shared` — only `shared.data_plane`'s checks run, driven from
  `$DOWNSTREAM_HOST`, which is then required; the script refuses to start
  without it (a shared check driven from the DUT itself would silently
  re-test `local.data_plane`'s code path instead, which is exactly the
  mistake this option exists to prevent).
- `both` (the default) — both roles' checks run; `$DOWNSTREAM_HOST` is
  required for the same reason.

Whichever role is excluded is recorded `NOT_TESTED` in the report, not
silently omitted, so a report from a `local`- or `shared`-only run still
states plainly what it did not check. `REMOTE_SSH_USER` and
`DOWNSTREAM_SSH_USER` default to `root`; `SSH` and `DOWNSTREAM_SSH` can
override their command and options. `PING_COUNT` defaults to 20,
`TRANSFER_BYTES` to 8 MiB, and `OUT_DIR` to `./checksum-offload-report`.
`DUT_DIAGNOSTICS_TOKEN` supplies an optional bearer token. The tool:

1. Reads `$LOCAL_IFACE`'s current offload feature flags via `ethtool -k` and
   records them, to restore exactly on exit (including on Ctrl-C).
2. Runs four offload combinations by default — all relevant features on, all
   off, TX checksumming off alone, and TSO/GSO off alone. This is a
   deliberately small slice of the full 2^6 power set: "all on" is the
   default production case, "all off" isolates whether the eBPF rewrite
   itself is correct independent of any offload, and the two single-feature
   cases isolate the specific offload most likely to interact badly with an
   in-place header rewrite (TX checksum insertion assumes the checksum field
   holds what software would have computed; segmentation offload assumes a
   single logical packet the driver replicates headers for). Every
   combination names every one of the six recognized features explicitly —
   an earlier version let a combination that only named the features it
   cared about silently inherit whatever the *previous* combination left
   every other feature at, so "TX checksum off, everything else on" and "TX
   checksum off, everything else however the last run left it" were
   impossible to tell apart from the report. Extend `offloadMatrix` in the
   Go tool if a specific NIC or driver needs finer coverage.
3. Reads every feature back with `ethtool -k` after attempting to set it. If
   the interface did not actually end up in the state a combination's name
   claims — a feature this NIC does not support, or the driver silently
   refusing or ignoring a change — that whole combination is recorded
   `UNSUPPORTED` in the report and none of its traffic checks run, rather
   than running them under a label that no longer describes the interface's
   real state (an earlier version of this script did exactly that).
4. For each combination that was actually applied, runs and captures (via
   `tcpdump`, on the DUT and `$REMOTE_HOST`):
   - A control transfer over the plain SSH connection from the DUT to
     `$REMOTE_HOST` (exercises the interface and its offload settings
     without going through any eBPF rewrite at all — a failure here means
     the NIC/driver combination itself is the problem, not this inbound).
   - If `$TEST_ROLE` is `local` or `both`: `local.data_plane`'s own FakeIP
     ICMP echo (IPv4, and IPv6 if `$REMOTE_IPV6` is set) and, if
     `$REMOTE_PORT_TCP`/`$REMOTE_PORT_UDP` are set, TCP/UDP transfers — all
     originated from the DUT itself, toward `$REMOTE_FAKEIP_TARGET`. If
     `$TEST_ROLE` is `shared`, these are skipped and recorded `NOT_TESTED`
     instead of running.
   - If `$TEST_ROLE` is `shared` or `both`: the same three checks again, but
     originated from `$DOWNSTREAM_HOST` over ssh instead of from the DUT —
     this is what actually exercises `shared.data_plane`. If `$TEST_ROLE` is
     `local`, these are skipped and recorded `NOT_TESTED` instead of running.
     If `$DUT_DIAGNOSTICS_URL` is also set, each of these additionally
     requires the DUT's own counter (`fakeip_icmp_replies` for the ICMP
     check, `rewrite_failures` staying flat for the TCP check) to move the
     way a real, correctly-processed packet would, not just that
     `$DOWNSTREAM_HOST` received something.
5. Records PASS/FAIL/UNSUPPORTED/NOT_TESTED to `$OUT_DIR/report.tsv` based on
   what the **receiving** side's kernel actually accepted and, for the TCP
   and UDP transfers, actually received correctly — never based on
   `tcpdump`'s own checksum annotation on the sending side. TCP and UDP
   checks compare a SHA-256 of the sent payload against a SHA-256 computed
   on the receiving end, not merely a byte count: an earlier version of this
   script treated any non-zero receipt as "received intact," which an
   independent review found would record PASS for a transfer that arrived
   truncated, corrupted, or even one whose own send command had already
   failed, as long as *something* showed up on the other end. UDP is
   genuinely best-effort, so a datagram that never arrives at all (the
   receiving side's file stays empty) is retried up to three times before
   being recorded a failure; a datagram that *did* arrive but hashes
   differently from what was sent is recorded FAIL immediately, on that
   attempt, never retried away, since that is corruption rather than mere
   loss and retrying past it would hide the exact defect this procedure
   exists to catch. This is a whole-payload content check, not a
   sequenced-per-packet one with its own separate loss/reorder/corruption
   thresholds — it proves the bytes that arrived are exactly the bytes that
   were sent (or that they are not), which is what "checksum/content
   integrity" means here; it does not additionally characterize reordering
   within a single transfer.
   A capture taken before the NIC's own checksum engine runs routinely says
   "incorrect" even for packets a real receiver accepts without issue; that
   is a property of capturing before TX offload, not a real defect, and
   treating it as one would make every run fail regardless of whether the
   eBPF rewrite is actually correct. This is why the receiving side's own
   accept/drop and content-hash behavior is authoritative and `tcpdump`'s
   inline checksum verdict is not used as a pass/fail signal at all — only
   as raw evidence to attach to a report when something else already
   failed.
6. Reads the report's own status column back — counting `PASS`, `FAIL`,
   `UNSUPPORTED`, and `NOT_TESTED` rows exactly, not by searching detail
   messages for the word "FAIL" — and prints a summary with one of five exit
   codes: `0` (at least one `PASS`, zero `FAIL`, zero `UNSUPPORTED` — a clean
   pass), `1` (at least one `FAIL`, checked first regardless of anything
   else), `2` (`INCONCLUSIVE`: zero `PASS` rows at all, meaning nothing was
   actually verified this run — every combination was `UNSUPPORTED`, for
   example an unsupported `ethtool` feature on every NIC/driver combination
   tried), `3` (`PARTIAL`: at least one `PASS` but also at least one
   `UNSUPPORTED`, meaning some but not all of the intended coverage actually
   ran), or `4` (`FATAL`: the report file itself could not be read back at
   this final step, even though the run wrote to it throughout — a
   materially different claim from `INCONCLUSIVE`, which means the report
   was read fine and genuinely contained no `PASS`). An earlier version of
   this script only ever searched the report for the literal word `FAIL`;
   if every combination came back `UNSUPPORTED` (`ethtool` unavailable, or
   the NIC lacking a required feature) there was no `FAIL` line to find, so
   the script printed "all recorded checks PASSed" and exited `0` even
   though not one packet had actually been checked. Exit code `0` from this
   script now specifically means real traffic checks ran and every one of
   them passed — never "nothing failed because nothing ran."

## Reading a failure

- **The run exits `4` (`FATAL`)**: the report file could not be read back
  at the very last step, after this run had been writing to it throughout
  every combination. This is not the same as `INCONCLUSIVE` and does not
  mean nothing passed — it means the summary itself could not be computed.
  Check whether `$OUT_DIR`/the report file was deleted, moved, or had its
  permissions changed by something else while this script was running.
- **The run exits `2` (`INCONCLUSIVE`)**: no check anywhere in this run
  actually passed — most likely every combination came back `UNSUPPORTED`.
  This is not evidence the eBPF rewrite is correct; nothing was verified.
  Fix whatever kept every combination from applying (see the `UNSUPPORTED`
  warnings on stderr) and re-run before drawing any conclusion.
- **The run exits `3` (`PARTIAL`)**: at least one check passed, but at least
  one combination was `UNSUPPORTED` and contributed nothing. Read the
  summary line and the report for exactly which combinations never ran, and
  treat those specifically as unverified — do not extrapolate a passing
  combination's result to a NIC state that was never actually tested.
- **A combination is recorded `UNSUPPORTED`**: the NIC or driver would not
  actually enter the state that combination's name claims — see the
  warnings the script printed to stderr while applying it for which
  specific feature. This is not a finding about the eBPF rewrite at all;
  none of that combination's checks ran.
- **A check is recorded `NOT_TESTED`**: `$TEST_ROLE` deliberately excluded
  it for this run (a `local`-only run leaves every `shared_*` check
  `NOT_TESTED`, and vice versa). This is not a finding either — re-run with
  `TEST_ROLE=both` (and `$DOWNSTREAM_HOST` set) to cover the excluded role.
- **Control transfer fails on some (applied) combination**: the NIC/driver
  itself cannot run with that offload combination on this hardware — not an
  eBPF issue. Fix the driver/firmware combination (or exclude it on this
  hardware) before drawing any conclusion about the eBPF rewrite paths.
- **Control transfer passes but a `local_*` or `shared_*` check fails on the
  same combination**: this is the actual finding this procedure exists to
  catch — an eBPF-rewritten packet is wire-incorrect specifically under that
  offload combination, in the specific data plane the failing check names.
  Attach the DUT's and `$REMOTE_HOST`'s `.pcap` files from `$OUT_DIR` to the
  report; the receiving side's capture (not the sending side's) is the one
  to inspect first, since it is the one downstream of any real offload
  computation.
- **A `shared_fakeip_icmp` check fails specifically because the DUT's
  counter did not advance**, while `$DOWNSTREAM_HOST` itself saw a correct
  reply: something other than this inbound's `shared.data_plane` answered
  the ping (another device on the segment, or `local.data_plane` if it is
  also enabled — see Roles above). This is a test-setup problem to fix, not
  evidence about the eBPF rewrite either way.
- **Everything passes with all offload features on and off**: the code
  checked in this round does not depend on this NIC's offload behavior in a
  way this procedure can detect. Record the NIC model, driver, and firmware
  version alongside the PASS result — a different NIC/driver is still an
  open question, not something this one clean run answers for every device.

## What this does not cover

- Android hardware. This procedure is written for the Linux-host case;
  Android's networking stack, driver model, and available tooling (`nc`,
  `tcpdump` availability, `ethtool` support) differ enough that it needs its
  own pass on a real device, not an adaptation of this script.
- TCX-specific offload interaction. The tool does not select attachment
  mechanism (TCX vs `clsact`) — that is controlled by the sing-box
  configuration already running on the DUT, not by this tool. Run the
  procedure once per mechanism if both need checking on the same hardware.
- Any offload feature `ethtool -k` does not report as one of the six the
  tool recognizes (`rx-checksumming`, `tx-checksumming`,
  `generic-segmentation-offload`, `tcp-segmentation-offload`,
  `generic-receive-offload`, `tx-udp-segmentation`). Extend
  `offloadFeatures` and `offloadMatrix` in the Go tool for a NIC that
  exposes something else relevant (for example a vendor-specific
  `rx-udp-gro-forwarding` or `tx-checksum-ip-generic` flag) — every
  combination has to keep naming every entry in `offloadFeatures` once it
  changes.
- Full attribution when `local.data_plane` and `shared.data_plane` are both
  enabled on the DUT: `$DUT_DIAGNOSTICS_URL`'s counters are summed across
  every data plane hosting `fakeip_icmp`, not broken down per role. Disable
  the role not under test on the DUT for an unambiguous read.
