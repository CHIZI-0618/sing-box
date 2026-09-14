//go:build with_ebpf && (linux || android)

package ebpf

// AttachmentInfo describes one active kernel attachment without exposing the
// loader's map, program, link, or file-descriptor representation.
type AttachmentInfo struct {
	InterfaceName  string `json:"interface_name"`
	InterfaceIndex int    `json:"interface_index,omitempty"`
	Role           string `json:"role"`
	Framing        string `json:"framing"`
	Mechanism      string `json:"mechanism"`
	FakeIPICMP     bool   `json:"fakeip_icmp"`
}
