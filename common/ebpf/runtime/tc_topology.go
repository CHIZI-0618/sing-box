//go:build with_ebpf && (linux || android)

package runtime

import (
	"github.com/sagernet/netlink"
	core "github.com/sagernet/sing-box/common/ebpf"
	E "github.com/sagernet/sing/common/exceptions"
)

func (d *tcDataPlane) attachmentStateChanged(localInterface string, sharedInterfaces []string) (bool, error) {
	d.access.Lock()
	defer d.access.Unlock()
	desired, err := d.desiredAttachmentState(localInterface, sharedInterfaces)
	if err != nil {
		return false, err
	}
	if tcAttachmentTopologyChanged(d.attachments, desired) {
		return true, nil
	}
	for _, attachment := range d.attachments {
		if localInterface == "" && attachment.role.local {
			if _, err = netlink.LinkByName(attachment.interfaceName); tcLinkNotFound(err) {
				continue
			}
			if err != nil {
				return false, err
			}
		}
		attached, err := attachment.filtersAttached(d.priority, d.backend)
		if err != nil {
			return false, err
		}
		if !attached {
			return true, nil
		}
	}
	return false, nil
}

type tcAttachmentState struct {
	index   int
	framing core.TCLinkFraming
	role    tcInterfaceRole
}

func desiredTCAttachmentState(
	localInterface string,
	sharedInterfaces []string,
	linkByName func(string) (netlink.Link, error),
) (map[string]tcAttachmentState, error) {
	roles := make(map[string]tcInterfaceRole, len(sharedInterfaces)+1)
	if localInterface != "" {
		roles[localInterface] = tcInterfaceRole{local: true}
	}
	for _, interfaceName := range sharedInterfaces {
		role := roles[interfaceName]
		role.shared = true
		roles[interfaceName] = role
	}
	interfaces := make(map[string]tcAttachmentState, len(roles))
	for interfaceName, role := range roles {
		link, err := linkByName(interfaceName)
		if err != nil && tcLinkNotFound(err) {
			continue
		}
		if err != nil {
			return nil, E.Cause(err, "find TC eBPF interface ", interfaceName)
		}
		if link == nil || link.Attrs() == nil {
			return nil, E.New("invalid TC eBPF interface ", interfaceName)
		}
		framing, err := tcLinkFraming(link)
		if err != nil {
			return nil, err
		}
		interfaces[interfaceName] = tcAttachmentState{
			index:   link.Attrs().Index,
			framing: framing,
			role:    role,
		}
	}
	return interfaces, nil
}

func tcAttachmentTopologyChanged(attachments []*tcInterfaceAttachment, desired map[string]tcAttachmentState) bool {
	if len(attachments) != len(desired) {
		return true
	}
	for _, attachment := range attachments {
		state, loaded := desired[attachment.interfaceName]
		if !loaded || state.index != attachment.interfaceIndex ||
			state.framing != attachment.framing || state.role != attachment.role {
			return true
		}
	}
	return false
}
