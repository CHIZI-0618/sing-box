# eBPF Inbound Reliability Work — Acceptance Evidence

Branch: `ebpf-fakeip-icmp-reply`. This document is the acceptance record for
items 1–10 of the eBPF inbound reliability engagement plus the item-13
real-hardware verification deliverable, covering the closing/acceptance
round of work. Items 11 and 12 are explicitly held per instruction and are
not addressed here. This file is written for an independent reviewer working
from this branch; it is not part of the public documentation site under
`docs/`.

## 1. Final commit

All code, test, and CI changes described in this document, including §12's
response to the first independent code review, §13's response to a second
one, and §14's response to a third, land at
`600850181c923bed7e4cd022bbe7227f51d21047`. This section is updated in place
each time this document itself is revised, rather than being re-derived —
this document's own commit necessarily lands after the hash it names.

Full commit range for the code/test/CI work this document evidences (oldest
first):

```
8876b2d4 ebpf: fix three real integration-test bugs, not environment noise
8f4d4cd7 ebpf: report next retry deadline and bypass_rule_set version per backend
fdb1e5e7 ebpf: shard UDP client/reply-socket tables by address, not port alone
6c41c44e ebpf: add item 13's real-hardware checksum/offload verification procedure
1494e1e4 ebpf: separate bypass_rule_set's policy version from its retry count
cb0619d3 ebpf: describe the UDP shard hash as statistical, not a capacity guarantee
b119971b ebpf: cover the seven remaining real ICMP send/receive combinations
b25760aa ci: run every common/ebpf real-kernel integration test, not four by name
e56f9386 ebpf: distinguish bypass_rule_set's expected policy from its confirmed one
7ea0be0f ebpf: add a strict mode so CI catches TCX silently degrading to clsact
4ff0a17c docs: add acceptance evidence for the eBPF reliability closing round
de7bf15f docs: clarify the acceptance report's own commit is not in its hash list
c0296e8e ebpf: clear stale filter/link references so external deletion self-heals
1a35d559 ebpf: fix a real data race between Diagnostics and shared-rewrite Close
698f43c8 ebpf: report needs_attention for an unrecoverable component, not normal
ac03b48e ebpf: wake the retry scheduler when a rule-set update fails
f04e0561 ebpf: count shared packet-rewrite UDP clients in UDPSessionCount too
2e640950 ebpf: mark a backend unknown when its own forward apply wrecks it, too
742772d1 ebpf: fix combination baseline drift and wrong traffic origin in offload script
5569e0bb docs: record the independent review's eight findings and this round's fixes
b1b7f4e7 ebpf: fix offload-verify script's coverage, content, and role checks
f05e751d docs: record the second independent review's three findings and this round's fix
60085018 ebpf: never let a UDP send-command failure skip inspecting the receipt
```

Working tree at HEAD is clean except one untracked, unrelated directory
(`.codex-remote-attachments/`, predating this work) and `outputs/` (the
independent reviews' own artifact bundles — `outputs/ebpf-review/`,
`outputs/ebpf-review-round2/`, and `outputs/ebpf-review-round3/` — left
exactly as delivered) — see §12, §13, and §14 for how those reviews'
findings were addressed.

## 2. Environment

```
Linux DESKTOP-2NTK853 6.18.33.2-microsoft-standard-WSL2 #1 SMP PREEMPT_DYNAMIC Thu Jun 18 21:54:43 UTC 2026 x86_64 GNU/Linux
Debian GNU/Linux 13 (trixie)
go version go1.26.8 linux/amd64
```

All testing in this document was performed inside WSL2 Debian on this
machine. No physical Linux hardware, no Android device, and no real GitHub
Actions run were used — see §8 for exactly what remains unverified as a
result.

## 3. Exact test commands and results

### 3.1 Full suite, root, strict TCX mode (the same invocation now wired into CI)

```sh
export PATH="$PATH:/usr/local/go/bin"
cd /mnt/e/sing-box
SING_BOX_EBPF_INTEGRATION=1 SING_BOX_EBPF_REQUIRE_TCX=1 \
  go test -tags with_ebpf,ebpf_integration -race -count=1 -v \
  ./common/ebpf/... ./protocol/ebpf/...
```

Result (re-run after §12's review-response commits; see that section):

```
ok  	github.com/sagernet/sing-box/common/ebpf	2.029s
ok  	github.com/sagernet/sing-box/protocol/ebpf	9.430s
```

**295 PASS / 0 FAIL / 0 SKIP** across both packages combined. `SING_BOX_EBPF_REQUIRE_TCX=1`
being set and producing zero skips/failures confirms every TCX-attachment
test in this run actually obtained a real TCX attachment on this kernel,
not a silent clsact fallback.

One test (`TestFakeIPICMPSharedRewriteAnswersARealIPv6ClientPing`) was
observed to fail once, with `IPv6 next header = 0, want ICMPv6`, in a single
full-suite run during this round, and passed on three immediate repeats in
isolation and on an immediate full-suite re-run. This reads as a timing
-sensitive flake in the netns test harness under full-suite load, not a
regression from anything in §12 — it is not touched by any of that section's
commits. Not root-caused further this round; flagged here rather than
silently reported as "285 PASS" from the clean re-run alone.

### 3.2 Full suite, non-root (same command, ordinary user, `SING_BOX_EBPF_REQUIRE_TCX` unset)

**233 PASS / 9 FAIL / 53 SKIP** (233+9+53 = 295, matching the root run's total exactly).

The 9 FAIL are all the same, pre-existing cause — these tests call
`t.Fatal("eBPF integration test requires root")` directly (not `t.Skip`)
when `euid != 0`, a test-authoring choice in this codebase, not a defect:

```
TestCgroupProgramMatrixIntegration
TestFakeIPICMPPassThroughIntegration
TestFakeIPICMPStatsCountsPassThroughNotOrdinaryTraffic
TestMapBatchIntegration
TestLRUFallbackBoundedIntegration
TestTCProgramRunIntegration
TestTCIPv6PathIsolationIntegration
TestTCFragmentPolicyIntegration
TestTCPolicyRoutingIntegration
```

All 9 pass in the root run (§3.1). The 52 SKIP are all `operation not
permitted` / `requires root` conditions raised by `t.Skipf` (map/program
creation, network-namespace creation) — every one was individually checked
against its logged reason; none is a masked, unidentified failure.

### 3.3 Cross-architecture `go vet`

```sh
for pair in "linux amd64" "linux arm64" "linux 386" "linux arm" "android arm64"; do
  GOOS=... GOARCH=... go vet -tags with_ebpf,ebpf_integration ./common/ebpf/... ./protocol/ebpf/...
done
```

All five platforms: no output (clean), for every file touched across every
commit in this closing round, including §12's review-response commits.

### 3.4 `gofmt`

This checkout stores files as CRLF in the working tree while git's blobs
are LF (`core.autocrlf=true`); `gofmt -l` alone flags essentially every file
in the repository, including ones this round never touched, purely from
that line-ending difference — `gofmt`'s own output is always LF regardless
of input. The reliable check used throughout was:

```sh
diff <(gofmt file) <(tr -d '\r' < file)
```

Every file touched in this round showed no diff by this method (i.e. no
real formatting issue) after one genuine formatting fix (a struct-field
alignment slip in `diagnostics.go`, corrected in the first commit of this
round).

## 4. The three previously-mischaracterized baseline failures — root cause, not environment

Corrected per direct instruction: these were originally described as
"pre-existing environment/dependency issues" based only on reproducing them
against a pre-round baseline, which confirmed they predated this round's
changes but never identified an actual cause. Root-caused below with
reproduction evidence; each was reverse-verified (revert the fix, confirm
the *exact* original failure text/panic reproduces, restore, reconfirm).

**Bug 1 — typed-nil interface, `common/ebpf/map_integration_helpers_test.go`**:
`countMapEntries` boxed a nil `[]byte` into `NextKeyBytes(key any)` on the
first loop iteration. A nil `[]byte` boxed into an `any` parameter is a
non-nil *typed* nil interface, not the literal `nil` the library checks for
to mean "start of iteration" — it tried to marshal an empty key instead.
Reverting the fix reproduces `can't marshal key: []uint8 doesn't marshal to
N bytes` exactly.

**Bug 2 — missing end-of-iteration check, same file**: this pinned
`cilium/ebpf` version's `Map.NextKeyBytes` returns a plain `(nil, nil)` at
end of iteration, not an `ErrKeyNotExist`/`ENOENT`-wrapped error; the
original code only checked for the latter. Reverting reproduces `BPF map
returned an unexpected key size: got 0 bytes, want N` (N = the real entry
count).

**Bug 3 — mismatched `TCConfig` in `common/ebpf/tc_program_run_integration_test.go`**:
`TestTCIPv6PathIsolationIntegration`'s first case targeted
`tcProgramSharedIngressEthernet` (loaded only when `EnableShared` is set)
while enabling only `EnableLocal`. The un-requested program slot in
`backend.runtime.programs[]` is `nil`; calling `.Run()` on it panics,
uncaught, aborting the whole test binary — meaning every test positioned
after it in an unfiltered run never executed at all, which is exactly what
the (now-fixed) `ebpf-verifier.yml` gap in §6 allowed to go unnoticed.
Reverting reproduces the identical panic trace (`Program.run(0x0, ...)`,
SIGSEGV) at the original line.

## 5. Diagnostics: policy version vs. attempt count vs. expected vs. confirmed

Three distinct, previously-conflated or previously-missing concepts, now
separated in `EBPFDiagnostics`:

| Field | Meaning | Advances when |
|---|---|---|
| `BypassRuleSetPolicyVersion` | The policy this inbound has last **confirmed** applying | A full apply attempt succeeds and its content differs from what was in effect |
| `BypassRuleSetExpectedPolicyVersion` | The policy this inbound is currently **trying to converge to** | Every apply attempt, successful or not, if its content differs from the *previous attempt's* content |
| `BypassRuleSetRetryCount` | How many times the scheduler has actually **retried** a previously-failed apply | Only inside `retryBypassRuleSetIfNeededLocked`; never on the original attempt or a fresh rule-set-triggered apply |
| `BypassRuleSetBackendState[name]` | Per-backend `{version, known}` | `version` = last confirmed version for that backend; `known=false` means its last operation (a compensating revert) itself failed, so `version` is a last-known-point, not a current-state claim |

Two real defects were found and fixed while implementing this, both
reverse-verified (break → confirm exact expected failure → restore →
reconfirm pass):

1. The very first cut of `BypassRuleSetExpectedPolicyVersion`/`PolicyVersion`
   collapsed into a single field that advanced on *every attempt* — an
   attempt counter mislabeled as a version. Fixed by making
   `BypassRuleSetPolicyVersion` advance only on confirmed success, with a
   separate `BypassRuleSetExpectedPolicyVersion` for the attempted target.
2. Even after that split, the version number for *which content is
   attempted* was computed by comparing the new policy against the last
   **confirmed** content, not the last **attempted** one. Two different
   failed attempts (e.g. two rule-set changes arriving before either one's
   retry fires) were then assigned the *same* version number, despite
   having genuinely different content, because both were compared against
   the same stuck confirmed baseline. Fixed by comparing each new attempt
   against `bypassRuleSetExpectedPolicy` (the last *attempted* content)
   instead. Test: `TestBypassRuleSetExpectedVersionTracksTheLatestAttemptEvenOnFailure`
   (`protocol/ebpf/inbound_policy_test.go`) — two different failed attempts
   are asserted to produce two different expected-version numbers, and the
   eventual successful retry is asserted to land on the *second* (latest),
   not the first, attempt's content.

`Known=false` (backend state uncertain after a failed revert) is likewise
tested directly (`TestApplyBypassCIDRPolicyLeavesBackendVersionOnFailedRevert`)
by making a real TC backend's own revert call fail (a policy larger than
`common/ebpf`'s compiled-in 65536-entry bypass-CIDR map capacity), not by a
mock/fake backend.

## 6. UDP reply-socket/client-table sharding

**Finding**: `udpReplySocketPool.shardIndex`, `udpClientTable.clientShard`,
and `sharedUDPClientTable.clientShard` all sharded purely by port
(`(port ^ port>>8) & 15`). The reply-socket pool is keyed by original
destination address:port; real UDP destinations concentrate heavily on a
handful of well-known ports (443, 53, ...) while varying in address, so
every destination sharing a port collapsed onto one shard regardless of how
many distinct addresses were involved — reproduced directly:
`TestUDPReplySocketPoolShardsSpreadAcrossDestinationPort` showed 256
distinct destination IPs all on port 443 landing 100% in one shard under
the old formula. The client tables have the identical weakness against
their own key (a LAN client's address).

**Fix**: `shardIndexForAddrPort`, one FNV-1a hash folding in every address
byte plus the port, shared by all three call sites. 4096 synthetic
destinations sharing one port land exactly 256 to a shard across all 16
shards under this hash — **a statement about that one sample, not a general
guarantee**, corrected explicitly in the code comment: FNV-1a is not a
cryptographic hash, and only `udpReplySocketPool` enforces any per-shard
capacity at all (the client tables have none).
`udpClientShardCount * udpReplySocketShardCapacity` is the pool's ceiling
under perfectly even placement, not a floor promised for every traffic
shape.

## 7. ICMP real-packet coverage matrix

All twelve applicable cells (IPv4/IPv6 × clsact/TCX × local/shared-socket_assign/shared-packet_rewrite)
now have a dedicated test that sends a real packet and verifies a real,
correctly-addressed, correctly-checksummed reply:

| Data plane | clsact v4 | clsact v6 | TCX v4 | TCX v6 |
|---|---|---|---|---|
| local | pre-existing | added this round | pre-existing | pre-existing |
| shared/socket_assign | pre-existing | added | added | added |
| shared/packet_rewrite | pre-existing | added | added | added |

`local + cgroup` is excluded from this matrix: it is an explicit,
documented architectural non-support (the cgroup hooks fire at the socket
syscall layer and never see a raw packet), not a coverage gap.

Every TCX case skips (or, under `SING_BOX_EBPF_REQUIRE_TCX=1`, fails — see
§9) rather than silently passing under clsact, and additionally asserts the
role-specific TCX link (`sharedICMPLink`/`icmpLink`) was actually attached.

A methodological note kept for the record: the first attempt at
reverse-verifying the new ICMPv6 checksum logic (swapping the pseudo-header's
source/destination arguments) produced no test failure at all, because that
sum adds every address word from both parameters into one accumulator and
is symmetric to the swap — it would not have caught a real corruption
either. This was caught before being reported as a passing check;
`TestICMPv6ChecksumDetectsCorruption` was written instead, corrupting a
built frame's bytes directly and confirming the parser's checksum flag
reacts, and *that* test was reverse-verified successfully (disabling the
checksum check produces the exact expected failure).

## 8. Item 13 — real-hardware checksum/offload verification

**Status: script and documentation delivered; hardware verification not executed.**

- `common/ebpf/testing/checksum_offload_verify.sh` — syntax-checked
  (`bash -n`) and linted (`shellcheck`, zero warnings), but never run
  against real hardware.
- `docs/manual/misc/ebpf-checksum-offload-verification.md` / `.zh.md` —
  procedure, required environment, and how to read a failure.
- Requires two real Linux hosts joined by a real NIC (not veth, not
  virtio-net — neither has real offload silicon behind it). No such
  environment was available in this session.

## 9. CI: `ebpf-verifier.yml`

**Gap found and fixed**: the "Load program matrix" step ran a privileged
`./common/ebpf` pass filtered to four tests by an anchored `-run` regex.
That list was never widened as more `ebpf_integration` tests were added, so
`TestTCIPv6PathIsolationIntegration` (§4, Bug 3) and four newer counter
tests (`TestFakeIPICMPStatsCountsPassThroughNotOrdinaryTraffic`,
`TestFakeIPICMPStatsZeroWhenDisabled`,
`TestSharedNetworkStatsReadCleanlyWithNoFailures`,
`TestSharedNetworkStatsIndependent`) never actually ran as root in CI.
Fixed by dropping the filter (renamed "Run common/ebpf real-kernel tests"),
matching how the adjacent `protocol/ebpf` step already runs its package
unfiltered, plus `-race`.

**TCX strict mode added**: `SING_BOX_EBPF_REQUIRE_TCX=1`, now set on the
`protocol/ebpf` step (ubuntu-24.04's kernel, 6.8+, is expected to support
TCX — it shipped in 6.6), turns every TCX-attachment test's
fallback-to-clsact-or-skip path into a hard failure via the shared
`requireOrSkipTCX` helper (`tc_fakeip_icmp_tcx_netns_test.go`), so a
regression that silently degrades TCX coverage to clsact is caught instead
of masked by a quiet skip. Left unset anywhere a kernel's TCX support is
not already established, so genuinely unsupported environments keep
skipping cleanly. The decision logic itself
(`tcxAttachmentOutcome`) is a pure function, unit-tested directly across
all four `(strictMode, attachmentType)` combinations
(`TestTCXAttachmentOutcome`) and reverse-verified.

**Not verified**: no real GitHub Actions run of this workflow — this branch
has no open pull request to trigger one against. §3.1's local run
reproduces the updated workflow step's exact command and passed cleanly,
which is the closest available substitute, but it is not the same as an
actual Actions run on `ubuntu-24.04`. It has also not been possible to
verify, on an actual kernel lacking TCX, that
`SING_BOX_EBPF_REQUIRE_TCX=1` genuinely fails a real attachment test rather
than the decision logic alone (which is unit-tested) — this environment's
kernel has TCX, so every real attachment test here takes the ordinary
"granted" path.

## 10. Explicitly unverified / out of scope

- **Items 11 and 12**: untouched, per instruction, across every round of
  this closing work.
- **Real GitHub Actions execution** of `ebpf-verifier.yml` (§9): not run;
  no open PR on this branch.
- **Android**: no Android device or emulator was used at any point in this
  round. `fakeip_icmp`'s Android-specific attachment path has no dedicated
  test coverage beyond what already existed before this round.
- **Real-hardware checksum/offload verification** (§8): script and
  documentation delivered, never executed.
- **`SING_BOX_EBPF_REQUIRE_TCX=1` against a genuinely TCX-less kernel**
  (§9): only the decision function is unit-tested; the end-to-end failure
  path through a real attachment test has not been observed, because this
  session's kernel has TCX.
- **The exact double-BPF-syscall failure in §12 finding #6** (a forward
  policy apply failing AND its own internal rollback also failing): fixed
  and covered by unit tests of the new `RequiresRebuild()` accessors
  themselves (forced into that state directly, bypassing the kernel), but
  the coordinator-level wiring in `inbound_policy.go` that reads
  `RequiresRebuild()` after a real `UpdateCompiledBypassCIDR` call has no
  live end-to-end test — reproducing the actual double failure needs a real
  eBPF map operation to fail partway and its own rollback to also fail,
  which is not practically triggerable through the public API in this
  environment. The reviewer's own finding disclosed the identical
  limitation.
- **One observed test flake** (§3.1): `TestFakeIPICMPSharedRewriteAnswersARealIPv6ClientPing`
  failed once under full-suite load and passed on every repeat; not
  root-caused further this round, and not touched by any §12 commit.

## 11. Scope discipline

No changes were made to anything outside what this closing round's
instructions named. In particular: no new features, no changes to items 11
or 12, and the one adjacent finding surfaced along the way that was *not*
fixed (rather than being folded in silently) is noted here for the record:
`ebpf-verifier.yml`'s original four-test filter predates this round and was
a pure CI-configuration gap, not application code — fixed in its own commit
(`b25760aa`) rather than bundled into any of the application-code commits
above.

## 12. Response to an independent code review

An independent review of commit `de7bf15f` (this document's own previous
revision) found eight issues, one P1 and seven P2, each with a concrete
reproduction (its own overlay test bundle is preserved, untouched, at
`outputs/ebpf-review/`). All eight are addressed below, each in its own
commit, each reverse-verified against the review's own reported symptom
where a live reproduction was practical.

### #1 [P1] — reconcile() returned success after repairing nothing

**Finding**: `filtersAttached` correctly detects an externally deleted
filter or externally detached TCX link, but `updateTCInterfaceAttachmentWithOps`'s
repair logic only re-attaches a field whose Go-side pointer is `nil` —
deleting a kernel object has no way to reach into this process and clear
the struct that described it, so the existing health-check tests only
passed because they manually nil'd the pointer right after simulating the
deletion, which is not what a real external deletion leaves behind.

**Fix** (`c0296e8e`): `tcInterfaceAttachment.clearStaleAttachments`, called
by `reconcile()` right before the repair attempt, checks each filter/link
individually (unlike `filtersAttached`, which short-circuits) and discards
the Go-side reference for any one the kernel no longer actually has. Both
existing health-check tests had their artificial pointer-nil removed and
now pass against the real repair path; the TCX test additionally switched
from `Close()` (which also invalidates the FD — a materially different
failure shape) to `link.Link.Detach()` (a real `BPF_LINK_DETACH`, FD left
open, matching the review's own raw-syscall reproduction). A new test
(`TestTCLocalFilterHealthCheckDetectsAndRepairsExternalDeletion`) proves
the fix also covers the ordinary local egress filter, not only the
fakeip_icmp filter attached alongside it, since the review named that as a
symmetric, unverified risk.

**Reverse-verified**: removing the `clearStaleAttachments` call reproduces
the review's exact reported symptom (`filtersAttached still reports
unhealthy immediately after repair`) in all three tests.

### #2 [P2] — data race between Diagnostics and shared-rewrite Close

**Finding**: `Diagnostics()` read `i.sharedRewrite` and
`i.sharedRewrite.dataPlane` with no lock, while `closeResources`' plain
field write and `sharedRewrite.Close`'s own `dataPlane` write (under
`lifecycleAccess`) happen with nothing serializing the two — confirmed with
`go test -race`.

**Fix** (`1a35d559`): extends this codebase's own existing pattern
(`tcDataPlaneAccess`/`cgroupBackendAccess` on `Inbound`, `backendAccess` on
`sharedRewrite` for `sharedBackend`) to the two fields that were missing
it — `sharedRewriteAccess` and `dataPlaneAccess`, each its own small
`RWMutex` with a getter/setter/take trio — rather than one broader lock
that risks the reentrancy/reverse-ordering the review specifically warned
against. Every existing caller now goes through the safe accessor.

**Reverse-verified**: `TestSharedRewriteDiagnosticsDoesNotRaceWithClose`
drives 2000 concurrent `Diagnostics()` calls against a real `Close()`;
temporarily reverting `dataPlaneInstance`/`takeDataPlane` to plain field
access reproduces a real `WARNING: DATA RACE` at the exact call site the
review reported.

### #3 [P2] — an unrecoverable component reported State=normal

**Finding**: `deriveDiagnosticsState` never checked for
`tcSharedRewriteUnrecoverable` at all; an unrecoverable backend with its
attachment record still present fell through every check to `normal`.

**Fix** (`698f43c8`): adds `EBPFDiagnostics.RecoveryUnrecoverable`, checked
first in `deriveDiagnosticsState` — ahead of the `waiting_for_interface`
checks, since an attachment that still exists but is unrecoverable needs
attention regardless. Writing the test for this surfaced a second,
related gap: `recordTCUpdateOutcome` overwrites `lastOutcome` wholesale
every round, and `updateTCInterfaces` can legitimately return before
re-evaluating a later component at all (an early return after a
local-interface-topology failure leaves it at `tcSharedRewriteUnknown`,
not `Settled`) — silently erasing a still-Unrecoverable result one round
later. Fixed by preserving the previous round's value for any component
that comes back `Unknown`.

**Reverse-verified**: removing the `RecoveryUnrecoverable` check reproduces
the exact reported `normal` state; removing the `Unknown`-preservation
reproduces the fault silently clearing itself on the following round.

### #4 [P2] — a failed rule-set update left the scheduler asleep

**Finding**: `updateBypassRuleSet`'s failure path set
`bypassRuleSetNeedsRetry` but never woke the scheduler, despite its own
comment claiming the scheduler would "pick this back up" — the scheduler
only runs a round on a network event or its ten-minute health-check tick.

**Fix** (`ac03b48e`): calls this package's own existing
`notifyTCInterfaceUpdate` (the same non-blocking wake the interface and
default-interface change handlers already use) from the failure path.

**Reverse-verified**: `TestUpdateBypassRuleSetWakesTheSchedulerOnFailure`;
removing the notification call reproduces the review's exact reported
symptom (nothing sent on the update channel).

### #5 [P2] — UDPSessionCount undercounted shared packet-rewrite clients

**Finding**: `UDPSessionCount` only ever read `i.udpClientTable` (local/TC),
never `sharedRewrite.sharedUDPClientTable` — a `packet_rewrite`-only
inbound with no local role reported 0 regardless of active clients.

**Fix** (`f04e0561`): adds `sharedUDPClientTable.count()` (mirroring
`udpClientTable.count()`'s shard-locking pattern) and sums both into one
field, documented as counting distinct clients, not bindings or flows.

**Reverse-verified**: `TestDiagnosticsUDPSessionCountIncludesSharedPacketRewriteClients`;
removing the shared-table addition reproduces the exact reported
`udp_session_count=0`.

### #6 [P2] — a backend's own forward-apply failure left it known=true

**Finding**: the bypass_rule_set coordinator only revised a backend's
`known`/the whole-inbound `bypassRuleSetInconsistent` when a *later*
backend's compensating revert failed — never when a backend's own forward
`UpdateCompiledBypassCIDR` failed with its **internal** rollback also
failing, which the backend's own code marks by invalidating itself
(requiring a rebuild). That backend was never in `applied` in the first
place, so the revert pass never reached it either.

**Fix** (`2e640950`): `TCBackend` and `CgroupBackend` gain a
`RequiresRebuild() bool` accessor, mirroring `SharedNetworkBackend`'s
existing one exactly. The coordinator checks it at each forward-apply
failure site (not the `SetBypassCIDRState` path, which only touches
in-memory counters and cannot itself require a rebuild) and marks that
backend `known=false` plus the whole inbound `bypassRuleSetInconsistent=true`.

**Verified**: `TestTCBackendRequiresRebuild`/`TestCgroupBackendRequiresRebuild`
cover the new accessors directly and are reverse-verified. **Not
independently live-tested**: the coordinator-level wiring itself — see §10.
Reproducing the actual double failure needs a real eBPF map update to fail
partway and its own rollback to also fail, which the review's own finding
already disclosed as impractical to trigger through the public API; this
round reached the same conclusion rather than working around it with a
mock.

### #7 [P2] — offload script combinations inherited leftover state

**Finding**: `OFFLOAD_MATRIX` entries naming only the features they cared
about silently inherited whatever the previous combination left every
other feature at; a driver-refused or unsupported feature was still
recorded as a mere warning, with the combination then possibly reporting
PASS under a label no longer matching the interface's real state.

**Fix** (`742772d1`): every `OFFLOAD_MATRIX` entry now names every one of
the six recognized features explicitly (`require_complete_combination`
fails loudly at definition time if a future entry omits one), and
`set_features` reads every feature back afterward, recording the whole
combination `UNSUPPORTED` (no traffic checks run) if the interface did not
actually reach the requested state.

**Verified**: by ad hoc extraction of the affected shell functions against
a faked `ethtool` (ordinary command substitution, not committed) —
`require_complete_combination` correctly rejects an incomplete entry and
accepts a complete one; `set_features` correctly distinguishes a
driver-refused feature, a silently-ignored one, and a combination that
genuinely applies. That exercise caught a real bug in this fix's own first
draft — the four real `OFFLOAD_MATRIX` entries did not mention
`tx-udp-segmentation` at all, which `require_complete_combination` would
have rejected outright — fixed before commit. Never run against real
hardware, unchanged from before.

### #8 [P2] — offload script could not actually verify shared.data_plane

**Finding**: every check sent traffic from the DUT itself, which only ever
exercises `local.data_plane`'s TC **egress** classifier —
`shared.data_plane`'s **ingress** classifier only sees traffic from a real
downstream client, so nothing in the script could verify it; worse, if
both roles were enabled, a DUT-originated "shared" check could report PASS
by way of `local.data_plane` silently answering it instead.

**Fix** (`742772d1`, same commit as #7): the script now names three roles
explicitly (DUT, `$REMOTE_HOST`, and a new `$DOWNSTREAM_HOST`) and adds a
parallel set of shared-role checks driven from `$DOWNSTREAM_HOST` over ssh.
A new `$DUT_DIAGNOSTICS_URL`, when set, additionally requires the DUT's own
`/ebpf` counters (`fakeip_icmp_replies`, `rewrite_failures`) to move the
way a genuinely-processed packet would. The doc states plainly that those
counters sum across every data plane hosting `fakeip_icmp`, not broken
down per role, and recommends disabling the role not under test for an
unambiguous read rather than claiming the script can disambiguate a
combined counter after the fact.

**Verified**: same ad hoc logic exercise as #7 (this is the same commit and
the same script). Never run against real hardware — this specifically
needs a third host this round never had.

### Summary

| # | Severity | Status | Live-verified |
|---|---|---|---|
| 1 | P1 | Fixed | Yes, 3 tests, reverse-verified |
| 2 | P2 | Fixed | Yes, race test, reverse-verified |
| 3 | P2 | Fixed | Yes, 2 tests, reverse-verified |
| 4 | P2 | Fixed | Yes, 1 test, reverse-verified |
| 5 | P2 | Fixed | Yes, 1 test, reverse-verified |
| 6 | P2 | Fixed | Accessor only; coordinator wiring not live-tested (§10) |
| 7 | P2 | Fixed | Logic-level only (faked `ethtool`); no real hardware |
| 8 | P2 | Fixed | Logic-level only (faked `ethtool`); no real hardware |

No production code outside what these eight findings named was touched.
`outputs/ebpf-review/` (the review's own artifact bundle) was read for
context and left completely untouched, uncommitted, exactly as delivered.

## 13. Response to a second independent code review

A second independent review of commit `5569e0bbf28300fff57f9ad9a1bf23552bb6bf6e`
(this document's own previous revision, i.e. after §12's eight fixes landed)
independently reproduced and confirmed findings #1–#5 above as closed, and
accepted #6's `RequiresRebuild()` wiring as correctly directioned on static
review, while explicitly noting that the accessor's own unit tests are not
equivalent to an end-to-end proof of the double-BPF-syscall-failure path
(§10 already carries this as an open item; this review did not close it,
and neither does this section). It found no new core-code issues. It did
find three P2 issues, all in `common/ebpf/testing/checksum_offload_verify.sh`
(item 13's real-hardware verification tooling), each with its own concrete
reproduction (its own review artifacts and script-regression driver are
preserved, untouched, at `outputs/ebpf-review-round2/`; the first review's
`outputs/ebpf-review/` was left untouched as well). All three are addressed
below, in one combined commit — the three fixes touch overlapping sections
of the same single script and interact with each other (the role selector
in C gates the checks whose content-verification C's own summary in A now
also has to count), the same reasoning that combined #7 and #8 above into
one commit.

### A. [P2] — the script declared success even when zero traffic checks ran

**Finding**: the final summary only ever searched the report for the
literal word `FAIL`. If every offload combination came back `UNSUPPORTED`
(`ethtool` unavailable, or the NIC lacking a required feature such as
`tx-udp-segmentation`), the report had no `FAIL` line and no valid `PASS`
line either, and the script still printed "all recorded checks PASSed" and
exited `0`. Reproduced with an all-local fake `ethtool`: four `UNSUPPORTED`
lines, zero traffic tests, `script_exit=0`, "all passed" text.

**Fix** (`b1b7f4e7`): the summary now counts `PASS`/`FAIL`/`UNSUPPORTED`/
`NOT_TESTED` exactly from the report's own tab-separated status column
(never a free-text substring search, which a detail message could
coincidentally match) and exits `0` only when at least one check passed and
none were `UNSUPPORTED`; `1` if any `FAIL` is present (checked first,
regardless of the rest); `2` (`INCONCLUSIVE`) when the pass count is zero,
meaning nothing was actually verified; `3` (`PARTIAL`) when the pass count
is nonzero but at least one combination was `UNSUPPORTED`.

**Verified**: an ad hoc, uncommitted scratchpad script exercised the exact
awk-based counting/exit-code logic against five synthetic report
compositions (all-`UNSUPPORTED`, mixed `PASS`+`UNSUPPORTED`, `FAIL` present
alongside `PASS`, all-`PASS`, and `PASS`+`NOT_TESTED` under a role-restricted
run) and got the intended exit code (2, 3, 1, 0, 0 respectively) in every
case. Never run against real hardware.

### B. [P2] — byte count was treated as content integrity

**Finding**: the TCP check compared only the number of bytes received and
called it "received intact"; the UDP check ignored the downstream send
command's own failure and PASSed on any non-zero receipt. The "matching
content, checked separately" language in the script's own log messages was
prose only — nothing enforced it. Reproduced by making the downstream send
command return failure while the received file held exactly one byte,
yielding a recorded PASS.

**Fix** (`b1b7f4e7`): all four transfer checks (local and shared, TCP and
UDP) now compare a SHA-256 of the sent payload against a SHA-256 computed
on the receiving end, and a failed send command is now itself an immediate
FAIL rather than being ignored. UDP retries up to three times, but only on
total loss (an empty received file) — inherent to UDP being best-effort;
any receipt that does not hash-match the sent payload is recorded FAIL on
that attempt immediately, never retried away, since that is evidence of
corruption rather than mere loss.

This intentionally implements whole-payload SHA-256 comparison rather than
the review's literal suggestion of sequenced, content-verified packets with
separate thresholds for loss, reorder, and corruption. The chosen approach
does verify real content integrity — the core of the finding — with a
clean binary correct/incorrect signal, but it does not characterize
reordering or partial corruption within a single UDP transfer the way a
sequence-numbered packet train would. This simplification is disclosed
here rather than presented as satisfying the suggestion literally.

**Verified**: the highest-fidelity ad hoc exercise in this engagement's
history for a shell-script fix — `check_local_tcp_rewrite` and
`check_local_udp_rewrite` were extracted verbatim via `awk`, sourced into a
throwaway harness, and run against real `127.0.0.1` TCP/UDP sockets with a
fake `ssh` that evaluates the "remote" command locally (standing in for a
genuine remote host, not merely mocking the decision logic). Real TCP
loopback with matching content: PASS with a genuine SHA-256. A remote
listener that cannot bind (privileged port): FAIL, not a false PASS. Real
UDP loopback with matching content: PASS. UDP total loss across three
retries (privileged port): FAIL after exactly three attempts, not silently
accepted. Critically, a same-byte-count, single-byte-corrupted transfer
(via a second fake ssh that flips one byte of the file the real listener
just wrote) now correctly produces FAIL on a genuine SHA-256 mismatch —
this is the exact false-positive scenario the review's finding B
describes, and it is now caught. The `sha256sum | cut` extraction idiom
itself was checked separately: distinct content produces distinct hashes,
identical content produces the identical hash across repeated computation,
and the extracted string is a clean 64-character hex value. Never run
against real hardware.

### C. [P2] — a shared-only configuration could not be cleanly validated

**Finding**: although `$DOWNSTREAM_HOST` had been added by the first
review's #8 fix, `run_one_combination` always called both the
local-origin and shared-origin checks unconditionally — there was no
switch to run only one role. The documentation's own guidance to disable
the role not under test for an unambiguous read was inconsistent with the
script's unconditional behavior: a DUT configured, per that same guidance,
with only `shared.data_plane` enabled had no local responder for the
unconditional local ping to reach, so it would fail (or take an unrelated
path) and take the whole run down even when the downstream shared
verification succeeded completely — meaning a pure-shared deployment, a
first-class configuration throughout this engagement, could not be cleanly
validated by this script at all.

**Fix** (`b1b7f4e7`): a new `TEST_ROLE` environment variable
(`local`/`shared`/`both`, default `both`) is validated at startup — an
unrecognized value, or `shared`/`both` without `$DOWNSTREAM_HOST` set,
exits immediately with an explanatory error — and gates which of the two
check blocks `run_one_combination` actually runs. The excluded role's
checks are recorded `NOT_TESTED` in the report, not silently omitted, so a
role-restricted run's own report states plainly what it did not check.
Both verification-procedure docs (`.md` and `.zh.md`) now document
`TEST_ROLE` and its validation rules directly, replacing the previous
inconsistent "disable the untested role on the DUT" guidance for this
specific ambiguity (that guidance still applies to the separate, narrower
`$DUT_DIAGNOSTICS_URL` counter-attribution ambiguity documented in "What
this does not cover").

**Verified**: an ad hoc, uncommitted scratchpad script drove the extracted
`TEST_ROLE` validation logic through six scenarios — an invalid role,
`shared` and `both` without `$DOWNSTREAM_HOST`, `local` without it, and
`shared`/`both` with it set — and every scenario was rejected or accepted
exactly as intended. Never run against real hardware; the finding itself
was confirmed by the reviewer via static control-flow reading, not a live
reproduction, and this fix's verification is at the same level.

### Regression check

The full suite was re-run after all three fixes landed, as root under WSL
Debian, the same invocation §3.1 uses:

```
ok  	github.com/sagernet/sing-box/protocol/ebpf	9.349s
ok  	github.com/sagernet/sing-box/common/ebpf	2.005s
```

Only the shell script and its two verification docs changed in this round;
this run is the standard full-suite sanity check this engagement performs
before every commit, not evidence specific to any of the three findings
themselves (which are shell-script-only and covered by the ad hoc
exercises above).

### What this round does not resolve

- **Real hardware remains unexecuted.** Every verification above is a
  logic-level or real-loopback exercise; none of it touches a physical NIC,
  `ethtool`, or a genuine remote/downstream host. The procedure is still,
  as documented, ready to run rather than a claim that hardware behavior
  has been checked.
- **`TestFakeIPICMPSharedRewriteAnswersARealIPv6ClientPing`'s earlier
  disclosed flake stays "cause unconfirmed."** The second review's own full
  regression pass did not encounter it, but explicitly declined to treat
  that as evidence the flake is resolved — not having touched the test
  file does not prove it is unrelated to other runtime changes either. Its
  one offered hypothesis (the read function may strictly parse the first
  received IPv6 frame without first filtering for the expected reply, so
  unrelated IPv6 control traffic could trigger a false parse failure) is
  named explicitly as an unverified direction to investigate, not a proven
  root cause, and no work was done on it this round — it stays out of
  scope until specifically taken up.
- Real GitHub Actions execution, Android hardware, and TCX-specific offload
  interaction on physical silicon remain unverified, unchanged from §10.

### Summary

| Finding | Severity | Status | Live-verified |
|---|---|---|---|
| A — false success on zero coverage | P2 | Fixed | Yes, exit-code logic against 5 synthetic reports |
| B — byte count as content integrity | P2 | Fixed | Yes, real TCP/UDP loopback + deliberate corruption test |
| C — cannot validate shared-only config | P2 | Fixed | Logic-level only (`TEST_ROLE` validation); no real hardware |

No production code, existing Go tests, or the acceptance evidence above §13
was modified by this round beyond what these three findings named. Both
`outputs/ebpf-review/` and `outputs/ebpf-review-round2/` (each review's own
artifact bundle) were read for context and left completely untouched,
uncommitted, exactly as delivered.

## 14. Response to a third independent code review

A third independent review of commits `b1b7f4e7` and `f05e751d` (HEAD at the
time) reproduced §13's fixes A and C and accepted both as acceptable for
their reviewed scope, and reproduced fix B's SHA-256 comparisons in all four
transfer functions, confirming whole-payload verification is adequate for
detecting the same-size/wrong-content false positive the second review
found — when the comparison is actually reached. That qualifier is the
finding: it found fix B's own retry loop had a gap the second review's
verification exercise had not covered.

### P2 — a UDP send failure skipped the receipt check instead of skipping only the retry decision

**Finding**: both `check_local_udp_rewrite` and `check_shared_udp_rewrite`
treated a nonzero exit from the send command as proof of total loss and
`continue`d to the next attempt without ever inspecting that attempt's
receipt. But a sender or its SSH connection can fail *after* already
transmitting some or all of a datagram — a nonzero send exit does not
establish that nothing arrived. The review's isolated regression harness
supplied a nonzero first-attempt sender exit together with a genuinely
received 65,000-byte datagram carrying the wrong hash, followed by a second
attempt that would succeed with correct content; both production functions
reported PASS on attempt 2, silently retrying past the corruption their own
documented policy says should fail immediately. The review was explicit
that this reproduces simulated command outcomes, not observed physical NIC
corruption.

**Fix** (`60085018`): both functions now capture the send command's exit
status but always proceed to wait for the receiver and inspect its receipt
— every attempt, regardless of that status. The send status is used only to
explain *why* a receipt came back empty (which is what the retry-on-total-
loss policy is for); it never again skips the receipt check by itself. A
nonempty receipt that does not hash-match the sent payload is an immediate
FAIL on that attempt, never retried away, whether or not the sender also
reported failure. Separately, the review's own suggestion that "missing or
unreadable receiver evidence must not be treated as an established
zero-length receipt" was also applied: the previous `stat ... || echo 0`
fallback folded a failed remote `stat` (evidence the check could not read)
into the same code path as a confirmed empty file. The two are now
distinguished — an unreadable receipt is retried with a warning that says
plainly the evidence could not be read, not that zero bytes were confirmed
received.

This is the review's primary suggested correction ("preserve sender status,
wait for the receiver, and inspect the receipt before deciding whether
retry is permissible"), not its offered alternative of conservatively
failing outright on any send-command failure. The primary fix was chosen
because it keeps the existing retry-on-total-loss-only design intact rather
than replacing it with a stricter policy the review only offered as a
fallback, and because it still correctly retries a send failure that
genuinely delivered nothing, which the alternative would fail immediately
even though nothing about that case is actually a violation of the
documented policy.

**Verified**: an ad hoc, uncommitted scratchpad harness reproduced the
review's own scenario against both `check_local_udp_rewrite` and
`check_shared_udp_rewrite` directly (extracted verbatim via `awk`, per this
engagement's established technique): attempt 1's send command fails while
the "remote" side nonetheless receives a corrupted 65,000-byte datagram,
and attempt 2 (were it reached) would succeed with correct content. Both
functions now report FAIL with a genuine SHA-256 mismatch on attempt 1 and
never reach attempt 2 — where the previous code retried past the corruption
and reported a false PASS. The requested regression coverage ("failed
sender plus corrupt receipt followed by a would-be successful retry, on
both roles") is exactly what this harness exercises. The second review's
own real-loopback regression harness (`test_offload_fixB.sh`: matching
content over real TCP/UDP sockets, a remote listener that cannot bind,
total loss retried three times, single-byte TCP corruption) was re-run
unchanged against the fixed functions and still passes, confirming the fix
did not regress any previously-verified behavior. `bash -n` and
`shellcheck -x` both clean; the full `go test -race` suite for `common/ebpf`
and `protocol/ebpf` still passes as root under WSL Debian, even though (as
the review itself notes about its own pass) this change touches only the
verification script, not the Go code the suite exercises. Never run against
real hardware.

### What this round does not resolve

Unchanged from §13: real hardware remains unexecuted; the
`TestFakeIPICMPSharedRewriteAnswersARealIPv6ClientPing` flake's root cause
remains unconfirmed (this review did not re-run the Go suite and does not
bear on it either way); real GitHub Actions, Android, and TCX-on-physical-
silicon remain unverified; items 11 and 12 remain held.

### Summary

| Finding | Severity | Status | Live-verified |
|---|---|---|---|
| UDP send failure skipped the receipt check | P2 | Fixed | Yes, reproduces the review's own scenario for both roles |

No production code, existing Go tests, or the acceptance evidence above §14
was modified by this round beyond this one finding. `outputs/ebpf-review/`,
`outputs/ebpf-review-round2/`, and `outputs/ebpf-review-round3/` (each
review's own artifact bundle) were read for context and left completely
untouched, uncommitted, exactly as delivered.
