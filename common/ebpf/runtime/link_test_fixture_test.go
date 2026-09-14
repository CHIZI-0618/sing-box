//go:build with_ebpf && (linux || android)

package runtime

import (
	"testing"

	"github.com/sagernet/netlink"
)

func createTestVethPair(t *testing.T, selfName, peerName string) (self, peer netlink.Link) {
	t.Helper()
	attributes := netlink.NewLinkAttrs()
	attributes.Name = selfName
	if err := netlink.LinkAdd(&netlink.Veth{LinkAttrs: attributes, PeerName: peerName}); err != nil {
		t.Fatalf("create veth pair: %v", err)
	}
	var err error
	self, err = netlink.LinkByName(selfName)
	if err != nil {
		t.Fatalf("find veth %s: %v", selfName, err)
	}
	peer, err = netlink.LinkByName(peerName)
	if err != nil {
		t.Fatalf("find veth peer %s: %v", peerName, err)
	}
	for _, networkLink := range []netlink.Link{self, peer} {
		if err = netlink.LinkSetUp(networkLink); err != nil {
			t.Fatalf("bring up %s: %v", networkLink.Attrs().Name, err)
		}
	}
	return self, peer
}
