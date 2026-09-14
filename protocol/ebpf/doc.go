//go:build with_ebpf && (linux || android)

// Package ebpf adapts the reusable kernel mechanisms in common/ebpf to the
// sing-box inbound lifecycle.
//
// This package owns user configuration, route-rule and rule-set translation,
// Android package-to-UID resolution, listener and UDP session handling,
// process metadata, router metadata, logging, and diagnostics. Kernel resource
// orchestration that is still here, including TC/TCX attachments, policy
// routing, veth devices, and related sysctls, is transitional and must move as
// complete ownership units before common/ebpf is extracted.
package ebpf
