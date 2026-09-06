# eBPF Inbound Reliability Work — Acceptance Evidence

Branch: `ebpf-fakeip-icmp-reply`. This document is the acceptance record for
items 1–10 of the eBPF inbound reliability engagement plus the item-13
real-hardware verification deliverable, covering the closing/acceptance
round of work. Items 11 and 12 are explicitly held per instruction and are
not addressed here. This file is written for an independent reviewer working
from this branch; it is not part of the public documentation site under
`docs/`.

## 1. Final commit

```
7ea0be0f9e7ef8456b4622e8c16c53d1a1a6e151
```

Full commit range for this closing/acceptance work (oldest first):

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
```

Working tree at HEAD is clean except one untracked, unrelated directory
(`.codex-remote-attachments/`) that predates this work and was never staged
or touched.

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

Result:

```
ok  	github.com/sagernet/sing-box/common/ebpf	2.001s
ok  	github.com/sagernet/sing-box/protocol/ebpf	9.267s
```

**287 PASS / 0 FAIL / 0 SKIP** across both packages combined. `SING_BOX_EBPF_REQUIRE_TCX=1`
being set and producing zero skips/failures confirms every TCX-attachment
test in this run actually obtained a real TCX attachment on this kernel,
not a silent clsact fallback.

### 3.2 Full suite, non-root (same command, ordinary user, `SING_BOX_EBPF_REQUIRE_TCX` unset)

**226 PASS / 9 FAIL / 52 SKIP** (226+9+52 = 287, matching the root run's total exactly).

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

All five platforms: no output (clean), for every file touched across all
ten commits in this closing round.

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

## 11. Scope discipline

No changes were made to anything outside what this closing round's
instructions named. In particular: no new features, no changes to items 11
or 12, and the one adjacent finding surfaced along the way that was *not*
fixed (rather than being folded in silently) is noted here for the record:
`ebpf-verifier.yml`'s original four-test filter predates this round and was
a pure CI-configuration gap, not application code — fixed in its own commit
(`b25760aa`) rather than bundled into any of the application-code commits
above.
