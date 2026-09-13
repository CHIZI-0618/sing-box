//go:build with_ebpf && (linux || android)

package ebpf

import (
	"testing"

	"github.com/sagernet/netlink"
	"github.com/sagernet/netlink/nl"

	"golang.org/x/sys/unix"
)

const tcTestRoutingMark uint32 = 1 << 30

// tcTestRuleAttribute is one netlink attribute of a synthetic dump message.
type tcTestRuleAttribute struct {
	kind  int
	value []byte
}

func tcTestUint32Attribute(kind int, value uint32) tcTestRuleAttribute {
	encoded := make([]byte, 4)
	nl.NativeEndian().PutUint32(encoded, value)
	return tcTestRuleAttribute{kind: kind, value: encoded}
}

// tcTestRuleMessage assembles an RTM_NEWRULE payload the way the kernel does, so
// the production parser is exercised on bytes rather than on a struct a test
// filled in.
func tcTestRuleMessage(header nl.RtMsg, attributes []tcTestRuleAttribute) []byte {
	message := header.Serialize()
	for _, attribute := range attributes {
		message = append(message, nl.NewRtAttr(attribute.kind, attribute.value).Serialize()...)
	}
	return message
}

// tcTestExpectedRule is the rule this process installs, which the parser
// compares each message against.
func tcTestExpectedRule(family int) netlink.Rule {
	return *tcPolicyRuleFor(family, tcTestRoutingMark, tcPolicyRoutingTable, tcPolicyRoutingPriority)
}

// tcTestOwnRuleHeader mirrors what the kernel reports for a rule this process
// installed: the routing action, no type of service, no prefix lengths, no
// flags, and the compat table because the real table does not fit a byte.
func tcTestOwnRuleHeader(family int) nl.RtMsg {
	var header nl.RtMsg
	header.Family = uint8(family)
	header.Type = nl.FR_ACT_TO_TBL
	header.Table = unix.RT_TABLE_COMPAT
	return header
}

// tcTestOwnRuleAttributes mirrors the attribute set the kernel emits for such a
// rule, including the two it attaches to every rule.
func tcTestOwnRuleAttributes() []tcTestRuleAttribute {
	return []tcTestRuleAttribute{
		tcTestUint32Attribute(unix.RTA_TABLE, tcPolicyRoutingTable),
		tcTestUint32Attribute(nl.FRA_SUPPRESS_PREFIXLEN, ^uint32(0)),
		// FRA_PROTOCOL is a single byte, not a word; the kernel sends it that way
		// on every rule, so the fixture has to as well.
		{kind: tcPolicyRuleAttributeProtocol, value: []byte{unix.RTPROT_BOOT}},
		tcTestUint32Attribute(nl.FRA_PRIORITY, tcPolicyRoutingPriority),
		tcTestUint32Attribute(nl.FRA_FWMARK, tcTestRoutingMark),
		tcTestUint32Attribute(nl.FRA_FWMASK, tcTestRoutingMark),
	}
}

func tcTestReplaceAttribute(attributes []tcTestRuleAttribute, kind int, value uint32) []tcTestRuleAttribute {
	replaced := make([]tcTestRuleAttribute, len(attributes))
	copy(replaced, attributes)
	for index := range replaced {
		if replaced[index].kind == kind {
			replaced[index] = tcTestUint32Attribute(kind, value)
			return replaced
		}
	}
	return append(replaced, tcTestUint32Attribute(kind, value))
}

func tcTestRemoveAttribute(attributes []tcTestRuleAttribute, kind int) []tcTestRuleAttribute {
	kept := make([]tcTestRuleAttribute, 0, len(attributes))
	for _, attribute := range attributes {
		if attribute.kind != kind {
			kept = append(kept, attribute)
		}
	}
	return kept
}

// TestParseTCPolicyRuleMessageOwnership covers which dump messages this process
// may claim. Claiming one means deleting it at startup and again on shutdown, so
// anything the kernel reports beyond the action, selector and attributes this
// code installs has to disown it.
func TestParseTCPolicyRuleMessageOwnership(t *testing.T) {
	for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
		for _, testCase := range []struct {
			name       string
			header     func(header *nl.RtMsg)
			attributes func([]tcTestRuleAttribute) []tcTestRuleAttribute
			owned      bool
		}{
			{name: "as the kernel reports our own rule", owned: true},
			// The header carries only a byte, so a table above 255 arrives as
			// RT_TABLE_COMPAT and the real value comes in the attribute. The
			// attribute therefore has to win: the header byte alone says nothing.
			{name: "table attribute overrides the header byte", header: func(h *nl.RtMsg) { h.Table = 200 }, owned: true},

			// The action, which netlink.RuleList cannot see at all.
			{name: "blackhole action", header: func(h *nl.RtMsg) { h.Type = nl.FR_ACT_BLACKHOLE }, owned: false},
			{name: "unreachable action", header: func(h *nl.RtMsg) { h.Type = nl.FR_ACT_UNREACHABLE }, owned: false},
			{name: "prohibit action", header: func(h *nl.RtMsg) { h.Type = nl.FR_ACT_PROHIBIT }, owned: false},
			{name: "nop action", header: func(h *nl.RtMsg) { h.Type = nl.FR_ACT_NOP }, owned: false},
			{name: "unspecified action", header: func(h *nl.RtMsg) { h.Type = nl.FR_ACT_UNSPEC }, owned: false},

			// Header-borne conditions.
			{name: "inverted", header: func(h *nl.RtMsg) { h.Flags |= netlink.FibRuleInvert }, owned: false},
			{name: "type of service", header: func(h *nl.RtMsg) { h.Tos = 4 }, owned: false},
			{name: "source prefix length", header: func(h *nl.RtMsg) { h.Src_len = 8 }, owned: false},
			{name: "destination prefix length", header: func(h *nl.RtMsg) { h.Dst_len = 8 }, owned: false},
			{
				name:   "other family",
				header: func(h *nl.RtMsg) { h.Family = uint8(unix.AF_INET + unix.AF_INET6 - family) },
				owned:  false,
			},

			// Selector differences.
			{
				name: "different priority",
				attributes: func(a []tcTestRuleAttribute) []tcTestRuleAttribute {
					return tcTestReplaceAttribute(a, nl.FRA_PRIORITY, tcPolicyRoutingPriority+1)
				},
				owned: false,
			},
			{
				name: "different table",
				attributes: func(a []tcTestRuleAttribute) []tcTestRuleAttribute {
					return tcTestReplaceAttribute(a, unix.RTA_TABLE, tcPolicyRoutingTable+1)
				},
				owned: false,
			},
			{
				name: "different mark",
				attributes: func(a []tcTestRuleAttribute) []tcTestRuleAttribute {
					return tcTestReplaceAttribute(a, nl.FRA_FWMARK, tcTestRoutingMark^1)
				},
				owned: false,
			},
			{
				name: "different mask",
				attributes: func(a []tcTestRuleAttribute) []tcTestRuleAttribute {
					return tcTestReplaceAttribute(a, nl.FRA_FWMASK, tcTestRoutingMark>>1)
				},
				owned: false,
			},
			{
				name:       "no mark",
				attributes: func(a []tcTestRuleAttribute) []tcTestRuleAttribute { return tcTestRemoveAttribute(a, nl.FRA_FWMARK) },
				owned:      false,
			},
			{
				name:       "no mask",
				attributes: func(a []tcTestRuleAttribute) []tcTestRuleAttribute { return tcTestRemoveAttribute(a, nl.FRA_FWMASK) },
				owned:      false,
			},
			{
				name:       "no priority",
				attributes: func(a []tcTestRuleAttribute) []tcTestRuleAttribute { return tcTestRemoveAttribute(a, nl.FRA_PRIORITY) },
				owned:      false,
			},
			{
				name:       "no table attribute",
				attributes: func(a []tcTestRuleAttribute) []tcTestRuleAttribute { return tcTestRemoveAttribute(a, unix.RTA_TABLE) },
				owned:      false,
			},

			// Suppression is reported on every rule, so only its value decides.
			{
				name: "suppress prefixlen configured",
				attributes: func(a []tcTestRuleAttribute) []tcTestRuleAttribute {
					return tcTestReplaceAttribute(a, nl.FRA_SUPPRESS_PREFIXLEN, 0)
				},
				owned: false,
			},
			{
				name: "suppress prefixlen one below the sentinel",
				attributes: func(a []tcTestRuleAttribute) []tcTestRuleAttribute {
					return tcTestReplaceAttribute(a, nl.FRA_SUPPRESS_PREFIXLEN, ^uint32(0)-1)
				},
				owned: false,
			},
			{
				name: "suppress prefixlen with the high bit set",
				attributes: func(a []tcTestRuleAttribute) []tcTestRuleAttribute {
					return tcTestReplaceAttribute(a, nl.FRA_SUPPRESS_PREFIXLEN, 1<<31)
				},
				owned: false,
			},
			{
				name: "suppress ifgroup at the sentinel",
				attributes: func(a []tcTestRuleAttribute) []tcTestRuleAttribute {
					return tcTestReplaceAttribute(a, nl.FRA_SUPPRESS_IFGROUP, ^uint32(0))
				},
				owned: true,
			},
			{
				name: "suppress ifgroup configured",
				attributes: func(a []tcTestRuleAttribute) []tcTestRuleAttribute {
					return tcTestReplaceAttribute(a, nl.FRA_SUPPRESS_IFGROUP, 0)
				},
				owned: false,
			},

			// Conditions carried as their own attributes.
			{
				name: "incoming interface",
				attributes: func(a []tcTestRuleAttribute) []tcTestRuleAttribute {
					return append(a, tcTestRuleAttribute{kind: nl.FRA_IIFNAME, value: []byte("wlan0\x00")})
				},
				owned: false,
			},
			{
				name: "outgoing interface",
				attributes: func(a []tcTestRuleAttribute) []tcTestRuleAttribute {
					return append(a, tcTestRuleAttribute{kind: nl.FRA_OIFNAME, value: []byte("wlan0\x00")})
				},
				owned: false,
			},
			{
				name: "goto target",
				attributes: func(a []tcTestRuleAttribute) []tcTestRuleAttribute {
					return append(a, tcTestUint32Attribute(nl.FRA_GOTO, 9000))
				},
				owned: false,
			},
			{
				name: "flow classifier",
				attributes: func(a []tcTestRuleAttribute) []tcTestRuleAttribute {
					return append(a, tcTestUint32Attribute(nl.FRA_FLOW, 3))
				},
				owned: false,
			},
			{
				name: "flow classifier with the high bit set",
				attributes: func(a []tcTestRuleAttribute) []tcTestRuleAttribute {
					return append(a, tcTestUint32Attribute(nl.FRA_FLOW, 1<<31))
				},
				owned: false,
			},
			{
				name: "tunnel id",
				attributes: func(a []tcTestRuleAttribute) []tcTestRuleAttribute {
					return append(a, tcTestRuleAttribute{kind: nl.FRA_TUN_ID, value: make([]byte, 8)})
				},
				owned: false,
			},
			{
				name: "uid range",
				attributes: func(a []tcTestRuleAttribute) []tcTestRuleAttribute {
					return append(a, tcTestRuleAttribute{kind: nl.FRA_UID_RANGE, value: make([]byte, 8)})
				},
				owned: false,
			},
			{
				name: "source prefix",
				attributes: func(a []tcTestRuleAttribute) []tcTestRuleAttribute {
					return append(a, tcTestRuleAttribute{kind: nl.FRA_SRC, value: []byte{10, 0, 0, 0}})
				},
				owned: false,
			},
			{
				name: "destination prefix",
				attributes: func(a []tcTestRuleAttribute) []tcTestRuleAttribute {
					return append(a, tcTestRuleAttribute{kind: nl.FRA_DST, value: []byte{10, 0, 0, 0}})
				},
				owned: false,
			},
			{
				name: "attribute this build does not know",
				attributes: func(a []tcTestRuleAttribute) []tcTestRuleAttribute {
					return append(a, tcTestUint32Attribute(tcPolicyRuleAttributeProtocol+42, 1))
				},
				owned: false,
			},
			{
				name: "short priority value",
				attributes: func(a []tcTestRuleAttribute) []tcTestRuleAttribute {
					return append(tcTestRemoveAttribute(a, nl.FRA_PRIORITY),
						tcTestRuleAttribute{kind: nl.FRA_PRIORITY, value: []byte{1, 2}})
				},
				owned: false,
			},
			{
				name: "short suppress value",
				attributes: func(a []tcTestRuleAttribute) []tcTestRuleAttribute {
					return append(tcTestRemoveAttribute(a, nl.FRA_SUPPRESS_PREFIXLEN),
						tcTestRuleAttribute{kind: nl.FRA_SUPPRESS_PREFIXLEN, value: []byte{0xff}})
				},
				owned: false,
			},
			{
				name: "short attribute value",
				attributes: func(a []tcTestRuleAttribute) []tcTestRuleAttribute {
					return append(a, tcTestRuleAttribute{kind: nl.FRA_PRIORITY + 100, value: []byte{1}})
				},
				owned: false,
			},
		} {
			t.Run(testCase.name, func(t *testing.T) {
				header := tcTestOwnRuleHeader(family)
				if testCase.header != nil {
					testCase.header(&header)
				}
				attributes := tcTestOwnRuleAttributes()
				if testCase.attributes != nil {
					attributes = testCase.attributes(attributes)
				}
				entry, ok, err := parseTCPolicyRuleMessage(
					tcTestRuleMessage(header, attributes),
					tcTestExpectedRule(family),
				)
				if err != nil {
					t.Fatalf("parse rule message: %v", err)
				}
				if !ok {
					t.Fatal("a full-length message was rejected as too short")
				}
				if entry.owned != testCase.owned {
					t.Fatalf("owned = %v, want %v (entry %+v)", entry.owned, testCase.owned, entry)
				}
			})
		}
	}
}

// TestParseTCPolicyRuleMessageReportsTable pins the other half of the entry: a
// rule the process cannot claim still has to report its table, or the callers
// cannot recognise a conflict on the table they want.
func TestParseTCPolicyRuleMessageReportsTable(t *testing.T) {
	family := unix.AF_INET
	header := tcTestOwnRuleHeader(family)
	header.Type = nl.FR_ACT_BLACKHOLE
	entry, ok, err := parseTCPolicyRuleMessage(
		tcTestRuleMessage(header, tcTestOwnRuleAttributes()),
		tcTestExpectedRule(family),
	)
	if err != nil {
		t.Fatalf("parse rule message: %v", err)
	}
	if !ok {
		t.Fatal("a full-length message was rejected as too short")
	}
	if entry.owned {
		t.Fatalf("a blackhole rule was claimed: %+v", entry)
	}
	if entry.table != tcPolicyRoutingTable {
		t.Fatalf("table = %d, want %d so the caller can report the conflict", entry.table, tcPolicyRoutingTable)
	}
	if entry.priority != tcPolicyRoutingPriority {
		t.Fatalf("priority = %d, want %d", entry.priority, tcPolicyRoutingPriority)
	}
}

// TestParseTCPolicyRuleMessageShortMessage covers a truncated dump message,
// which must be skipped rather than read past its end.
func TestParseTCPolicyRuleMessageShortMessage(t *testing.T) {
	full := tcTestRuleMessage(tcTestOwnRuleHeader(unix.AF_INET), tcTestOwnRuleAttributes())
	for _, length := range []int{0, 1, unix.SizeofRtMsg - 1} {
		entry, ok, err := parseTCPolicyRuleMessage(full[:length], tcTestExpectedRule(unix.AF_INET))
		if err != nil {
			t.Fatalf("parse %d-byte message: %v", length, err)
		}
		if ok {
			t.Fatalf("a %d-byte message was accepted as a rule: %+v", length, entry)
		}
	}
}

// TestParseTCPolicyRuleMessageAcceptsCrashLeftover pins the recovery case: the
// rule this process installs must still be recognised when it is found already
// in place, which is what lets a crashed run's leftover be reclaimed.
func TestParseTCPolicyRuleMessageAcceptsCrashLeftover(t *testing.T) {
	for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
		entry, ok, err := parseTCPolicyRuleMessage(
			tcTestRuleMessage(tcTestOwnRuleHeader(family), tcTestOwnRuleAttributes()),
			tcTestExpectedRule(family),
		)
		if err != nil {
			t.Fatalf("parse rule message: %v", err)
		}
		if !ok || !entry.owned {
			t.Fatalf("a leftover of this process's own rule was not recognised: %+v", entry)
		}
	}
}
