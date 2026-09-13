//go:build with_ebpf && (linux || android)

package ebpf

import (
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/sagernet/netlink"
	commonEBPF "github.com/sagernet/sing-box/common/ebpf"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"
)

// tcxStrictModeEnv, when set to "1", turns a TCX attachment falling back to
// clsact (or otherwise not being granted) from a skip into a hard failure.
// Set this in a CI environment already known to support TCX (see
// ebpf-verifier.yml, which sets it for GitHub Actions' ubuntu-24.04
// runners) so a regression that silently degrades every TCX test in this
// package to clsact-only coverage is caught, instead of being masked by
// every affected test quietly skipping -- a skip and a "TCX regressed to
// clsact everywhere" both look identical in a test summary otherwise.
// Left unset, an environment genuinely without TCX support (an older
// kernel, a constrained container) still skips these tests cleanly, which
// remains correct for a general contributor machine never expected to have
// TCX in the first place.
const tcxStrictModeEnv = "SING_BOX_EBPF_REQUIRE_TCX"

// requireOrSkipTCX is the shared decision behind every TCX "OrSkip"
// attachment helper in this package (attachFakeIPICMPOrSkip,
// attachSharedRewriteOrSkip): attachmentType == "tcx" is always fine;
// anything else either fails (tcxStrictModeEnv set) or skips (unset), so a
// caller reads as "this attempted TCX and did not get it" without
// duplicating the environment check at every call site.
// tcxAttachmentOutcome is requireOrSkipTCX's decision, factored out as a
// pure function so it can be unit-tested directly. A subtest's t.Fatal
// marks every ancestor test as failed too, automatically -- there is no way
// to unit-test "this correctly calls t.Fatal under these conditions" via a
// nested t.Run without the enclosing test itself reporting FAIL, which
// would be indistinguishable from the check actually being broken. Testing
// the decision as an ordinary pure function sidesteps that entirely, and
// leaves requireOrSkipTCX itself as a thin, obviously-correct wrapper that
// every real attachment test already exercises via its "tcx" (ok=true)
// path on this environment, which does have TCX support.
func tcxAttachmentOutcome(strictMode bool, attachmentType string) (ok, fatal bool) {
	if attachmentType == "tcx" {
		return true, false
	}
	return false, strictMode
}

func requireOrSkipTCX(t *testing.T, attachmentType string) {
	t.Helper()
	ok, fatal := tcxAttachmentOutcome(os.Getenv(tcxStrictModeEnv) == "1", attachmentType)
	if ok {
		return
	}
	if fatal {
		t.Fatalf(
			"%s=1 (this environment is configured to require TCX) but attachmentType=%q: "+
				"TCX attachment fell back to clsact or was otherwise unavailable, which this mode "+
				"treats as a regression to investigate, not an environment limitation to skip past",
			tcxStrictModeEnv, attachmentType,
		)
	}
	t.Skipf("this kernel did not grant a TCX attachment (attachmentType=%q); TCX is not available here", attachmentType)
}

// TestTCXAttachmentOutcome is a plain, no-root, no-kernel unit test of
// requireOrSkipTCX's decision logic across all four (strictMode,
// attachmentType) combinations that matter.
func TestTCXAttachmentOutcome(t *testing.T) {
	cases := []struct {
		name           string
		strictMode     bool
		attachmentType string
		wantOK         bool
		wantFatal      bool
	}{
		{"tcx granted, strict mode off", false, "tcx", true, false},
		{"tcx granted, strict mode on", true, "tcx", true, false},
		{"clsact fallback, strict mode off: skip, not fail", false, "clsact", false, false},
		{"clsact fallback, strict mode on: fail, not skip", true, "clsact", false, true},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			ok, fatal := tcxAttachmentOutcome(testCase.strictMode, testCase.attachmentType)
			if ok != testCase.wantOK || fatal != testCase.wantFatal {
				t.Fatalf(
					"tcxAttachmentOutcome(%v, %q) = (ok=%v, fatal=%v), want (ok=%v, fatal=%v)",
					testCase.strictMode, testCase.attachmentType, ok, fatal, testCase.wantOK, testCase.wantFatal,
				)
			}
		})
	}
}

// newRealFakeIPICMPBackendWithIPv6 is newRealFakeIPICMPBackend plus a FakeIP
// IPv6 range and local/shared IPv6 interception, for the IPv6 real-ping
// coverage neither the original clsact test nor this file's TCX tests could
// otherwise reach.
func newRealFakeIPICMPBackendWithIPv6(t *testing.T) *commonEBPF.TCBackend {
	t.Helper()
	policy, err := commonEBPF.CompilePolicy(commonEBPF.PolicyConfig{
		EnableTCP:  true,
		FakeIPIPv4: netip.MustParsePrefix("198.18.0.0/15"),
		FakeIPIPv6: netip.MustParsePrefix("fc00::/18"),
	})
	if err != nil {
		t.Fatalf("compile policy: %v", err)
	}
	backend, err := commonEBPF.PrepareTC(commonEBPF.TCConfig{
		ListenerPort:     23457,
		EnableLocal:      true,
		EnableShared:     true,
		EnableIPv4:       true,
		EnableLocalIPv6:  true,
		EnableSharedIPv6: true,
		EnableTCP:        true,
		Policy:           policy,
		FakeIPICMPReply:  true,
	})
	if err != nil {
		t.Skipf("cannot prepare a real TC eBPF backend in this environment: %v", err)
	}
	return backend
}

// attachFakeIPICMPOrSkip attaches with the given priority and, when priority
// requests TCX (1) but this kernel does not actually grant a TCX
// attachment, defers to requireOrSkipTCX -- skip on a general environment,
// fail on one configured via tcxStrictModeEnv to require TCX -- since
// attachTCInterfaceWithLock falls back to clsact silently, and a test that
// claims to cover TCX must not pass having silently exercised clsact
// instead.
func attachFakeIPICMPOrSkip(
	t *testing.T,
	backend *commonEBPF.TCBackend,
	interfaceName string,
	index int,
	role tcInterfaceRole,
	priority uint16,
) *tcInterfaceAttachment {
	t.Helper()
	lock, err := acquireTCInterfaceLock(interfaceName, index)
	if err != nil {
		t.Fatalf("acquire the interface lock: %v", err)
	}
	attachment, err := attachTCInterfaceWithLock(
		netlink.LinkByName,
		backend,
		interfaceName,
		tcAttachmentState{index: index, framing: commonEBPF.TCLinkFramingEthernet, role: role},
		false,
		priority,
		lock,
		true,
	)
	if err != nil {
		t.Fatalf("attach the interface: %v", err)
	}
	if priority == 1 && attachment.attachmentType != "tcx" {
		_ = attachment.Close()
		requireOrSkipTCX(t, attachment.attachmentType)
	}
	return attachment
}

// TestFakeIPICMPLocalReplyAnswersARealPingViaTCX is
// TestFakeIPICMPLocalReplyAnswersARealPing over the attachment mechanism
// production actually defaults to. The clsact test forces priority=2
// specifically so it cannot silently exercise this path instead; this test
// exists so TCX itself is not left completely unverified against a real
// packet. Skips (does not fail) on a kernel without TCX support.
func TestFakeIPICMPLocalReplyAnswersARealPingViaTCX(t *testing.T) {
	enterTestNetworkNamespace(t)
	backend := newRealFakeIPICMPBackend(t)
	t.Cleanup(func() { _ = backend.Close() })

	const fakeIPTarget = "198.18.0.1"
	self := setupFakeIPICMPPingVeth(t, "sbicmpx0", "sbicmpx1", fakeIPTarget)

	const priority = 1 // default: TCX is attempted.
	attachment := attachFakeIPICMPOrSkip(t, backend, "sbicmpx0", self.Attrs().Index, tcInterfaceRole{local: true}, priority)
	t.Cleanup(func() { _ = attachment.Close() })
	if attachment.localICMPLink == nil {
		t.Fatal("the fakeip_icmp TCX link was not attached alongside the ordinary one")
	}

	if err := pingFakeIPICMPTarget(t, fakeIPTarget, 5*time.Second); err != nil {
		t.Fatalf("read a reply: %v (the request may have gone to the wire instead of being answered)", err)
	}
}

// TestFakeIPICMPHealthCheckDetectsAndRepairsAMissingTCXLink is the TCX
// mirror of TestFakeIPICMPHealthCheckDetectsAndRepairsAMissingClsactFilter:
// same drift-detect-repair sequence, but against a real TCX link instead of
// a clsact filter, since filtersAttached's TCX branch and its clsact branch
// are separate code paths that each need their own real-kernel proof.
func TestFakeIPICMPHealthCheckDetectsAndRepairsAMissingTCXLink(t *testing.T) {
	enterTestNetworkNamespace(t)
	backend := newRealFakeIPICMPBackend(t)
	t.Cleanup(func() { _ = backend.Close() })

	const fakeIPTarget = "198.18.0.1"
	self := setupFakeIPICMPPingVeth(t, "sbicmpy0", "sbicmpy1", fakeIPTarget)

	const priority = 1
	attachment := attachFakeIPICMPOrSkip(t, backend, "sbicmpy0", self.Attrs().Index, tcInterfaceRole{local: true}, priority)
	t.Cleanup(func() { _ = attachment.Close() })

	if err := pingFakeIPICMPTarget(t, fakeIPTarget, 5*time.Second); err != nil {
		t.Fatalf("ping before breaking anything: %v", err)
	}

	// Simulate the fakeip_icmp TCX link vanishing on its own, exactly as the
	// clsact test simulates a vanished filter, leaving the ordinary TCX link
	// and this process's own file descriptor for the ICMP one completely
	// untouched: link.Link.Detach() issues BPF_LINK_DETACH without closing
	// the link's FD, the same effect an external `bpftool net detach` (or
	// equivalent) run outside this process would have -- unlike Close(),
	// which would also invalidate the FD itself and is a materially
	// different failure shape (Info() then fails outright with EBADF,
	// rather than succeeding but reporting a link no longer actually
	// attached to anything).
	detachable, ok := attachment.localICMPLink.(interface{ Detach() error })
	if !ok {
		t.Fatalf("localICMPLink (%T) does not support Detach", attachment.localICMPLink)
	}
	if err := detachable.Detach(); err != nil {
		t.Fatalf("detach the fakeip_icmp TCX link to simulate drift: %v", err)
	}

	attached, err := attachment.filtersAttached(priority, backend)
	if err != nil {
		t.Fatalf("filtersAttached: %v", err)
	}
	if attached {
		t.Fatal("filtersAttached reported this attachment healthy with the fakeip_icmp TCX link missing")
	}

	if err = pingFakeIPICMPTarget(t, fakeIPTarget, 2*time.Second); err == nil {
		t.Fatal("ping still answered after the fakeip_icmp TCX link was closed — the drift is not real")
	}

	healthyMainLink := attachment.localLink
	dataPlane := &tcDataPlane{backend: backend, attachments: []*tcInterfaceAttachment{attachment}, priority: priority}
	if err = dataPlane.reconcile("sbicmpy0", nil, nil); err != nil {
		t.Fatalf("reconcile did not repair the missing fakeip_icmp TCX link: %v", err)
	}
	repaired := dataPlane.attachments[0]
	if repaired.localLink != healthyMainLink {
		t.Fatal("repair replaced the ordinary TCX link instead of leaving the still-healthy one alone")
	}
	if repaired.localICMPLink == nil {
		t.Fatal("repair did not restore the fakeip_icmp TCX link")
	}
	attached, err = repaired.filtersAttached(priority, backend)
	if err != nil {
		t.Fatalf("filtersAttached after repair: %v", err)
	}
	if !attached {
		t.Fatal("filtersAttached still reports unhealthy immediately after repair")
	}

	if err = pingFakeIPICMPTarget(t, fakeIPTarget, 5*time.Second); err != nil {
		t.Fatalf("ping after repair: %v", err)
	}
}

// setupFakeIPICMPPingVethIPv6 is setupFakeIPICMPPingVeth's IPv6 counterpart:
// a veth pair, a global IPv6 address, a route to the FakeIP v6 range through
// it, a static neighbor entry for the FakeIP target (skipping the same
// unresolved-neighbor stall the IPv4 test avoids), and rp_filter is not a
// factor for IPv6 the way it is for IPv4 so nothing needs clearing there.
func setupFakeIPICMPPingVethIPv6(t *testing.T, selfName, peerName, fakeIPTarget string) netlink.Link {
	t.Helper()
	attributes := netlink.NewLinkAttrs()
	attributes.Name = selfName
	veth := &netlink.Veth{LinkAttrs: attributes, PeerName: peerName}
	if err := netlink.LinkAdd(veth); err != nil {
		t.Fatalf("create veth pair: %v", err)
	}
	self, err := netlink.LinkByName(selfName)
	if err != nil {
		t.Fatalf("find veth: %v", err)
	}
	peer, err := netlink.LinkByName(peerName)
	if err != nil {
		t.Fatalf("find veth peer: %v", err)
	}
	for _, link := range []netlink.Link{self, peer} {
		if err = netlink.LinkSetUp(link); err != nil {
			t.Fatalf("bring up %s: %v", link.Attrs().Name, err)
		}
	}
	// IFA_F_NODAD skips Duplicate Address Detection, which otherwise leaves
	// the address "tentative" (unusable as a source address, causing the
	// echo request itself to fail with EADDRNOTAVAIL) for about a second
	// after it is added — a real, deterministic wait this test has no
	// reason to depend on when nothing on this isolated veth could actually
	// be a duplicate.
	selfAddress := &netlink.Addr{
		IPNet: &net.IPNet{IP: net.ParseIP("2001:db8::1"), Mask: net.CIDRMask(64, 128)},
		Flags: unix.IFA_F_NODAD,
	}
	if err = netlink.AddrAdd(self, selfAddress); err != nil {
		t.Fatalf("address the veth: %v", err)
	}
	fakeIPRoute := &netlink.Route{
		LinkIndex: self.Attrs().Index,
		Dst:       &net.IPNet{IP: net.ParseIP("fc00::"), Mask: net.CIDRMask(18, 128)},
	}
	if err = netlink.RouteAdd(fakeIPRoute); err != nil {
		t.Fatalf("route the FakeIP v6 prefix through the veth: %v", err)
	}
	neighbor := &netlink.Neigh{
		LinkIndex:    self.Attrs().Index,
		Family:       netlink.FAMILY_V6,
		State:        netlink.NUD_PERMANENT,
		IP:           net.ParseIP(fakeIPTarget),
		HardwareAddr: peer.Attrs().HardwareAddr,
	}
	if err = netlink.NeighAdd(neighbor); err != nil {
		t.Fatalf("add a static neighbor entry for the FakeIP v6 target: %v", err)
	}
	return self
}

// pingFakeIPICMPTargetV6 is pingFakeIPICMPTarget for ICMPv6: same real
// round trip, same amplification/address/checksum assertions, over
// golang.org/x/net/icmp and ipv6 instead of ipv4.
func pingFakeIPICMPTargetV6(t *testing.T, fakeIPTarget string, deadline time.Duration) error {
	t.Helper()
	conn, err := icmp.ListenPacket("ip6:ipv6-icmp", "::")
	if err != nil {
		t.Fatalf("open a raw ICMPv6 socket: %v", err)
	}
	defer conn.Close()

	identifier := 0x2345 + int(time.Now().UnixNano()&0xff)
	sequence := 9
	payload := []byte("fakeip-icmp-v6-reply-test-payload")
	request := icmp.Message{
		Type: ipv6.ICMPTypeEchoRequest, Code: 0,
		Body: &icmp.Echo{ID: identifier, Seq: sequence, Data: payload},
	}
	requestBytes, err := request.Marshal(nil)
	if err != nil {
		t.Fatalf("marshal the echo request: %v", err)
	}

	if err = conn.SetDeadline(time.Now().Add(deadline)); err != nil {
		t.Fatalf("set a deadline: %v", err)
	}
	if _, err = conn.WriteTo(requestBytes, &net.IPAddr{IP: net.ParseIP(fakeIPTarget)}); err != nil {
		t.Fatalf("send the echo request: %v", err)
	}

	buffer := make([]byte, 1500)
	replyLength, peerAddress, err := conn.ReadFrom(buffer)
	if err != nil {
		return err
	}
	if replyLength > len(requestBytes) {
		t.Fatalf("reply is %d bytes, longer than the %d-byte request — an amplification, not a reply",
			replyLength, len(requestBytes))
	}
	if addr, ok := peerAddress.(*net.IPAddr); !ok || addr.IP.String() != fakeIPTarget {
		t.Fatalf("reply source = %v, want it to still carry the FakeIP address %s", peerAddress, fakeIPTarget)
	}
	reply, err := icmp.ParseMessage(58 /* iana.ProtocolIPv6ICMP */, buffer[:replyLength])
	if err != nil {
		t.Fatalf("parse the reply: %v", err)
	}
	if reply.Type != ipv6.ICMPTypeEchoReply {
		t.Fatalf("reply type = %v, want an echo reply", reply.Type)
	}
	if reply.Code != 0 {
		t.Fatalf("reply code = %d, want 0", reply.Code)
	}
	echo, ok := reply.Body.(*icmp.Echo)
	if !ok {
		t.Fatalf("reply body = %T, want *icmp.Echo", reply.Body)
	}
	if echo.ID != identifier || echo.Seq != sequence {
		t.Fatalf("reply identifier/sequence = %d/%d, want %d/%d", echo.ID, echo.Seq, identifier, sequence)
	}
	if string(echo.Data) != string(payload) {
		t.Fatalf("reply payload = %q, want %q unchanged", echo.Data, payload)
	}
	// ICMPv6's checksum covers a pseudo-header (source, destination, length,
	// next-header), which this raw socket's read does not hand back — RFC
	// 1071's plain self-sum trick does not apply here the way it does for
	// ICMPv4. icmp.ParseMessage already rejects a message too short or
	// structurally malformed to be a real echo reply; the pseudo-header
	// checksum arithmetic itself is exercised directly by
	// TestFakeIPICMPPassThroughIntegration's real BPF_PROG_TEST_RUN cases in
	// common/ebpf, not re-derived here from a raw socket that cannot see it.
	return nil
}

// TestFakeIPICMPLocalReplyAnswersARealIPv6PingViaTCX is the IPv6 local
// reply's first real end-to-end proof: every other fakeip_icmp test to date
// either forces clsact (the IPv4 test) or never leaves the parser/pass-through
// level (fakeip_icmp_program_run_integration_test.go's IPv6 cases). Skips on
// a kernel without TCX support, the same as the IPv4 TCX test.
func TestFakeIPICMPLocalReplyAnswersARealIPv6PingViaTCX(t *testing.T) {
	enterTestNetworkNamespace(t)
	backend := newRealFakeIPICMPBackendWithIPv6(t)
	t.Cleanup(func() { _ = backend.Close() })

	const fakeIPTarget = "fc00::1"
	self := setupFakeIPICMPPingVethIPv6(t, "sbicmpz0", "sbicmpz1", fakeIPTarget)

	const priority = 1
	attachment := attachFakeIPICMPOrSkip(t, backend, "sbicmpz0", self.Attrs().Index, tcInterfaceRole{local: true}, priority)
	t.Cleanup(func() { _ = attachment.Close() })
	if attachment.localICMPLink == nil {
		t.Fatal("the fakeip_icmp TCX link was not attached alongside the ordinary one")
	}

	if err := pingFakeIPICMPTargetV6(t, fakeIPTarget, 5*time.Second); err != nil {
		t.Fatalf("read a reply: %v (the request may have gone to the wire instead of being answered)", err)
	}
}
