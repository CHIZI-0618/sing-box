# Standalone extraction contract

This document is the hand-off checklist for moving the kernel mechanism into a
standalone module. It describes the intended end state; it does not create a
second module inside the sing-box repository.

## Dependency direction

The standalone module may depend directly on the upstream releases of:

- `github.com/cilium/ebpf`
- `github.com/sagernet/netlink`
- `github.com/sagernet/sing`
- `go4.org/netipx`
- `golang.org/x/sys`

It must not depend on `github.com/sagernet/sing-box`, `sing-tun`, a fork of
`sing`, or an application logging/configuration package. The temporary
`github.com/sagernet/sing-box/common/ebpf/internal/bpfgen` import is a
self-import and changes to the new module path when the package moves.

sing-box depends on the standalone module in one direction and remains
responsible for interpreting its own configuration and route rules.

## Atomic migration units

Move all of `common/ebpf` first, including `native/`, `internal/bpfgen/`, the
generation Makefile, test fixtures, and the source/object manifest. BPF C
sources, both endian variants of generated objects, Go ABI declarations, map
layouts, program selection, and loaders are one versioned unit and must never
be split across repositories or releases.

The in-tree preparation has already grouped each runtime under
`common/ebpf/runtime`. Move each directory as a complete resource owner:

### TC socket-assignment runtime

- `runtime/tc_dataplane.go`
- `runtime/tc_reconcile.go`
- `runtime/tc_netlink.go`
- `runtime/tc_delivery.go`
- `runtime/tc_routing.go`
- `runtime/tc_topology.go`
- their unit and network-namespace tests

This unit owns the TC/TCX links or filters, interface locks, clsact fallback,
delivery veth, policy rules/routes, modified sysctls, retired resources,
rollback, and the `TCBackend`. No raw link, filter, qdisc, route, sysctl record,
or program FD becomes public API.

### Shared packet-rewrite runtime

- `runtime/shared_rewrite_dataplane.go`
- its attachment, sysctl, health, rollback, race, and network-namespace tests

This unit owns its `SharedNetworkBackend`, TC/TCX attachments, interface locks,
per-interface `route_localnet` changes, retired resources, and rollback. Its
only application interactions are the explicit callbacks for userspace-flow
invalidation, readiness, and warning delivery. It must not retain the sing-box
adapter.

The generic TC attachment primitives and TCX capability cache are shared by
these two runtimes inside the standalone module. Do not duplicate them or move
only `tc_netlink.go` as a public helper package.

## Stable consumer surface

The sing-box adapter should consume only:

- policy/config value types and compiler functions;
- cgroup, self-bypass, process-tracker, redirect-route, TC, and shared-network
  lifecycle owners;
- TC and shared runtime constructors;
- reconciliation, enable/disable, health, close, and value-only diagnostic
  snapshots;
- explicit callback values that contain no sing-box types.

The exported `runtime.TCRuntime` and
`runtime.SharedPacketRewriteRuntime` interfaces are the mechanism contracts;
the adapter aliases them behind its bridge files. During extraction only those
bridge import paths change; inbound startup, monitoring, diagnostics, retry
scheduling, and shutdown do not change.

Keep the following in `protocol/ebpf`:

- JSON options, defaulting, and validation;
- sing-box route-rule and rule-set translation;
- Android package/user to UID conversion;
- listener construction and accepted-connection metadata;
- process lookup/cache integration;
- UDP NAT/session and transparent reply socket pools;
- router, Clash API, counters, warning rate limits, and user-facing logs.

## Lifetime invariants

Every exported resource owner must be nil-safe where documented, have an
idempotent `Close`, and retain enough state to retry cleanup after a partial
detach failure. Cleanup order is:

1. stop callbacks and reconciliation workers;
2. disable interception in the control map;
3. detach active and retired links/filters;
4. remove policy routing and restore sysctls;
5. remove delivery links;
6. close programs and maps;
7. release process-external interface/resource locks.

Startup failure uses the same owner and reverse-order cleanup. A runtime may
remove only routes, rules, qdiscs, sysctls, links, and attachments it created or
positively reclaimed as its own. It must never delete an unrelated object's
state solely because a numeric handle matches.

## ABI and release rules

- Regenerate little- and big-endian objects together after any BPF C or ABI
  change.
- Require the source/object manifest freshness check in CI.
- Version the Go ABI and embedded objects in the same module release.
- Keep optional kernel features on probed fallback paths; do not infer vendor
  kernel capability from the release string alone.
- Preserve verifier logs and typed capability results at the public boundary.

## Extraction acceptance gate

Before switching sing-box to the standalone module, require all of the
following:

```text
go test -tags with_ebpf ./...
go test -race -tags with_ebpf ./...
go vet -tags with_ebpf ./...
make check
```

Also run privileged network-namespace tests for TCX and clsact fallback,
interface recreation, partial detach retry, delivery-veth repair, policy-route
collision/rollback, shared `route_localnet` restore, and fake-IP ICMP paths.
Verify builds with `with_ebpf` both enabled and disabled and on little- and
big-endian targets. `boundary_test.go` must continue to reject every sing-box
application import anywhere in the extracted source and test tree.

Only after these gates pass should the external repository/module be created
and sing-box's bridge imports switched. This avoids a long-lived nested module
or a compatibility fork while the ownership boundary is still changing.
