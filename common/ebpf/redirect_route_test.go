//go:build with_ebpf && (linux || android)

package ebpf

import (
	"net/netip"
	"testing"

	"golang.org/x/sys/unix"
)

func TestLocalRouteSetZeroValueIsClosed(t *testing.T) {
	var routes LocalRouteSet
	if !routes.IsClosed() {
		t.Fatal("zero-value local route set owns routes")
	}
	if err := routes.Close(); err != nil {
		t.Fatalf("close zero-value local route set: %v", err)
	}
}

func TestSelectRedirectPrefixRejectsAddressFamilyMismatch(t *testing.T) {
	_, err := SelectRedirectPrefix(
		unix.AF_INET,
		[]netip.Prefix{netip.MustParsePrefix("fd00::/64")},
		nil,
	)
	if err == nil {
		t.Fatal("accepted an IPv6 redirect prefix for the IPv4 family")
	}
}
