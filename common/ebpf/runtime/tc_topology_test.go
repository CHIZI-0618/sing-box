//go:build with_ebpf && (linux || android)

package runtime

import (
	"errors"
	"net"
	"testing"

	"github.com/sagernet/netlink"
	core "github.com/sagernet/sing-box/common/ebpf"

	"golang.org/x/sys/unix"
)

func TestDesiredTCAttachmentState(t *testing.T) {
	links := map[string]int{"wlan2": 12, "rndis0": 27}
	interfaces, err := desiredTCAttachmentState("wlan2", []string{"wlan2", "missing0", "rndis0"}, func(name string) (netlink.Link, error) {
		index, loaded := links[name]
		if !loaded {
			return nil, unix.ENODEV
		}
		return testEthernetLink(name, index), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(interfaces) != 2 || interfaces["wlan2"].role != (tcInterfaceRole{local: true, shared: true}) ||
		interfaces["rndis0"].role != (tcInterfaceRole{shared: true}) {
		t.Fatalf("unexpected desired interfaces: %+v", interfaces)
	}
	if interfaces["wlan2"].framing != core.TCLinkFramingEthernet {
		t.Fatalf("unexpected wlan2 framing: %v", interfaces["wlan2"].framing)
	}
	expectedErr := errors.New("lookup failed")
	_, err = desiredTCAttachmentState("", []string{"wlan2"}, func(string) (netlink.Link, error) { return nil, expectedErr })
	if !errors.Is(err, expectedErr) {
		t.Fatalf("unexpected lookup error: %v", err)
	}
}

func TestTCAttachmentTopologyChanged(t *testing.T) {
	attachment := func(name string, index int, role tcInterfaceRole) *tcInterfaceAttachment {
		return &tcInterfaceAttachment{interfaceName: name, interfaceIndex: index, framing: core.TCLinkFramingEthernet, role: role}
	}
	state := func(index int, role tcInterfaceRole) tcAttachmentState {
		return tcAttachmentState{index: index, framing: core.TCLinkFramingEthernet, role: role}
	}
	testCases := []struct {
		name        string
		attachments []*tcInterfaceAttachment
		desired     map[string]tcAttachmentState
		changed     bool
	}{
		{"empty", nil, map[string]tcAttachmentState{}, false},
		{"appeared", nil, map[string]tcAttachmentState{"wlan2": state(12, tcInterfaceRole{shared: true})}, true},
		{"unchanged", []*tcInterfaceAttachment{attachment("wlan2", 12, tcInterfaceRole{shared: true})}, map[string]tcAttachmentState{"wlan2": state(12, tcInterfaceRole{shared: true})}, false},
		{"deleted", []*tcInterfaceAttachment{attachment("wlan2", 12, tcInterfaceRole{shared: true})}, map[string]tcAttachmentState{}, true},
		{"recreated", []*tcInterfaceAttachment{attachment("wlan2", 12, tcInterfaceRole{shared: true})}, map[string]tcAttachmentState{"wlan2": state(31, tcInterfaceRole{shared: true})}, true},
		{"role changed", []*tcInterfaceAttachment{attachment("wlan0", 8, tcInterfaceRole{local: true, shared: true})}, map[string]tcAttachmentState{"wlan0": state(8, tcInterfaceRole{local: true})}, true},
		{"framing changed", []*tcInterfaceAttachment{attachment("rmnet_data2", 21, tcInterfaceRole{local: true})}, map[string]tcAttachmentState{"rmnet_data2": {index: 21, framing: core.TCLinkFramingRawIP, role: tcInterfaceRole{local: true}}}, true},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			if changed := tcAttachmentTopologyChanged(testCase.attachments, testCase.desired); changed != testCase.changed {
				t.Fatalf("unexpected topology result: %v", changed)
			}
		})
	}
}

func testEthernetLink(name string, index int) netlink.Link {
	return &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: name, Index: index, EncapType: "ether", HardwareAddr: net.HardwareAddr{0, 1, 2, 3, 4, 5}}}
}
