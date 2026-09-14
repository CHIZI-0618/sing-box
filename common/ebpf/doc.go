//go:build with_ebpf && (linux || android)

// Package ebpf implements the Linux kernel-facing mechanisms used by the
// sing-box eBPF inbound.
//
// The package owns BPF source and generated objects, their Go/C ABI, map and
// program loading, capability selection, kernel policy state, and the cgroup
// attachments whose lifetime is inseparable from those objects. It deliberately
// does not interpret sing-box configuration, routing rules, outbound selection,
// process metadata, or connection/session semantics. Those application-facing
// responsibilities belong to protocol/ebpf.
//
// This boundary is intended to make the package extractable as a standalone Go
// module. New code in this package must not import sing-box application
// packages. The temporary self-import of internal/bpfgen is the sole exception
// while the package remains in the sing-box module.
package ebpf
