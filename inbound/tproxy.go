package inbound

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/redir"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/control"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/udpnat"
)

type TProxy struct {
	myInboundAdapter
	autoTProxy option.AutoTProxyOptions
	needSu     bool
	suPath     string
	udpNat     *udpnat.Service[netip.AddrPort]
}

func NewTProxy(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.TProxyInboundOptions) (*TProxy, error) {
	tproxy := &TProxy{
		myInboundAdapter: myInboundAdapter{
			protocol:      C.TypeTProxy,
			network:       options.Network.Build(),
			ctx:           ctx,
			router:        router,
			logger:        logger,
			tag:           tag,
			listenOptions: options.ListenOptions,
		},
		autoTProxy: common.PtrValueOrDefault(options.AutoTProxy),
	}
	if tproxy.autoTProxy.Enabled {
		if !C.IsAndroid {
			return nil, E.New("auto tproxy is only supported on Android")
		}
		userId := os.Getuid()
		if userId != 0 {
			suPath, err := exec.LookPath("/bin/su")
			if err == nil {
				tproxy.needSu = true
				tproxy.suPath = suPath
			} else if tproxy.autoTProxy.ContinueOnNoPermission {
				tproxy.autoTProxy.Enabled = false
			} else {
				return nil, E.Extend(E.Cause(err, "root permission is required for auto tproxy"), os.Getenv("PATH"))
			}
		}
		if tproxy.autoTProxy.MarkID == "" {
			tproxy.autoTProxy.MarkID = "0x12c"
		}
		if tproxy.autoTProxy.TableID == "" {
			tproxy.autoTProxy.TableID = "300"
		}
		//		if router.DefaultMark() != 0 {
		//			defaultMark := router.DefaultMark()
		//		}

	}
	var udpTimeout time.Duration
	if options.UDPTimeout != 0 {
		udpTimeout = time.Duration(options.UDPTimeout)
	} else {
		udpTimeout = C.UDPTimeout
	}
	tproxy.connHandler = tproxy
	tproxy.oobPacketHandler = tproxy
	tproxy.udpNat = udpnat.New[netip.AddrPort](int64(udpTimeout.Seconds()), tproxy.upstreamContextHandler())
	tproxy.packetUpstream = tproxy.udpNat
	return tproxy, nil
}

func (t *TProxy) Start() error {
	err := t.myInboundAdapter.Start()
	if err != nil {
		return err
	}
	var tproxytcpPortStr string
	var tproxyudpPortStr string
	if t.tcpListener != nil {
		err = control.Conn(common.MustCast[syscall.Conn](t.tcpListener), func(fd uintptr) error {
			return redir.TProxy(fd, M.SocksaddrFromNet(t.tcpListener.Addr()).Addr.Is6())
		})
		if err != nil {
			return E.Cause(err, "configure tproxy TCP listener")
		}
		tproxytcpPortStr = F.ToString(M.AddrPortFromNet(t.tcpListener.Addr()).Port())
	}
	if t.udpConn != nil {
		err = control.Conn(t.udpConn, func(fd uintptr) error {
			return redir.TProxy(fd, M.SocksaddrFromNet(t.udpConn.LocalAddr()).Addr.Is6())
		})
		if err != nil {
			return E.Cause(err, "configure tproxy UDP listener")
		}
		tproxyudpPortStr = F.ToString(M.AddrPortFromNet(t.udpConn.LocalAddr()).Port())
	}
	if t.autoTProxy.Enabled {
		t.cleanupTProxy()
		err = t.setupTProxy(tproxytcpPortStr, tproxyudpPortStr)
		if err != nil {
			var exitError *exec.ExitError
			if errors.As(err, &exitError) && exitError.ExitCode() == 13 && t.autoTProxy.ContinueOnNoPermission {
				t.logger.Error(E.Cause(err, "setup auto tproxy"))
				return nil
			}
			t.cleanupTProxy()
			return E.Cause(err, "setup auto tproxy")
		}
	}
	return nil
}

func (t *TProxy) Close() error {
	if t.autoTProxy.Enabled {
		t.cleanupTProxy()
	}
	return t.myInboundAdapter.Close()
}

func (t *TProxy) setupTProxy(tproxytcpPortStr, tproxyudpPortStr string) error {
	rules := `
iptables -w 100 -t mangle -N EXTERNAL
iptables -w 100 -t mangle -N LOCAL
`

	myUid := F.ToString(uint32(os.Getuid()))
	myGid := F.ToString(uint32(os.Getgid()))
	markID := t.autoTProxy.MarkID
	tableID := t.autoTProxy.TableID
	rules += "\niptables -w 100 -t mangle -A LOCAL -j RETURN -m owner --uid-owner " + myUid + " --gid-owner " + myGid

	if t.autoTProxy.IgnoreOutList != nil {
		var ignoreoutlist []string
		ignoreoutlist = t.autoTProxy.IgnoreOutList
		rules += strings.Join(common.Map(ignoreoutlist, func(ignoreout string) string {
			return "\niptables -w 100 -t mangle -A LOCAL -j RETURN -o " + ignoreout
		}), "\n")
	}

	if tproxyudpPortStr != "" {
		rules += "\niptables -w 100 -t mangle -A LOCAL -p udp --dport 53 -j MARK --set-mark " + markID
		rules += "\niptables -w 100 -t mangle -A EXTERNAL -p udp --dport 53 -j TPROXY --on-port " + tproxyudpPortStr + " --tproxy-mark " + markID
	}

	rules += strings.Join(common.FlatMap(t.router.(adapter.Router).InterfaceFinder().Interfaces(), func(it control.Interface) []string {
		return common.Map(common.Filter(it.Addresses, func(it netip.Prefix) bool { return it.Addr().Is4() }), func(it netip.Prefix) string {
			return "\niptables -w 100 -t mangle -A EXTERNAL -j RETURN -d " + it.String() +
				"\niptables -w 100 -t mangle -A LOCAL -j RETURN -d " + it.String()
		})
	}), "\n")
	intranet := []string{"0.0.0.0/8", "10.0.0.0/8", "100.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4", "255.255.255.255/32"}
	rules += strings.Join(common.Map(intranet, func(it string) string {
		return "\niptables -w 100 -t mangle -A EXTERNAL -j RETURN -d " + it +
			"\niptables -w 100 -t mangle -A LOCAL -j RETURN -d " + it
	}), "\n")

	if tproxytcpPortStr != "" {
		rules += "\niptables -w 100 -t mangle -A EXTERNAL -p tcp -i lo -j TPROXY --on-port " + tproxytcpPortStr + " --tproxy-mark " + markID
	}
	if tproxyudpPortStr != "" {
		rules += "\niptables -w 100 -t mangle -A EXTERNAL -p udp -i lo -j TPROXY --on-port " + tproxyudpPortStr + " --tproxy-mark " + markID
	}
	if t.autoTProxy.ApList != nil {
		var aplist []string
		aplist = t.autoTProxy.ApList
		if tproxytcpPortStr != "" {
			rules += strings.Join(common.Map(aplist, func(ap string) string {
				return "\niptables -w 100 -t mangle -A EXTERNAL -p tcp -i " + ap + " -j TPROXY --on-port " + tproxytcpPortStr + " --tproxy-mark " + markID
			}), "\n")
		}
		if tproxyudpPortStr != "" {
			rules += strings.Join(common.Map(aplist, func(ap string) string {
				return "\niptables -w 100 -t mangle -A EXTERNAL -p udp -i " + ap + " -j TPROXY --on-port " + tproxyudpPortStr + " --tproxy-mark " + markID
			}), "\n")
		}
	}

	if tproxytcpPortStr != "" {
		rules += "\niptables -w 100 -t mangle -A LOCAL -p tcp -j MARK --set-mark " + markID
	}
	if tproxyudpPortStr != "" {
		rules += "\niptables -w 100 -t mangle -A LOCAL -p udp -j MARK --set-mark " + markID
	}

	rules += "\niptables -w 100 -t mangle -I PREROUTING -j EXTERNAL" +
		"\niptables -w 100 -t mangle -I OUTPUT -j LOCAL"

	rules += "\nip rule add fwmark " + markID + " table " + tableID +
		"\nip route add local default dev lo table " + tableID

	for _, ruleLine := range strings.Split(rules, "\n") {
		ruleLine = strings.TrimSpace(ruleLine)
		if ruleLine == "" {
			continue
		}
		t.logger.Debug("# ", ruleLine)
	}
	return t.runAndroidShell(rules)
}

func (t *TProxy) cleanupTProxy() {
	rules := `
iptables -w 100 -t mangle -D OUTPUT -j LOCAL
iptables -w 100 -t mangle -D PREROUTING -j EXTERNAL

iptables -w 100 -t mangle -F LOCAL
iptables -w 100 -t mangle -X LOCAL

iptables -w 100 -t mangle -F EXTERNAL
iptables -w 100 -t mangle -X EXTERNAL
`
	markID := t.autoTProxy.MarkID
	tableID := t.autoTProxy.TableID
	rules += "\nip rule del fwmark " + markID + " table " + tableID +
		"\nip route flush table " + tableID

	for _, ruleLine := range strings.Split(rules, "\n") {
		ruleLine = strings.TrimSpace(ruleLine)
		if ruleLine == "" {
			continue
		}
		//		t.logger.Debug("# ", ruleLine)
	}
	_ = t.runAndroidShell(rules)
}

func (t *TProxy) runAndroidShell(content string) error {
	var command *exec.Cmd
	if t.needSu {
		command = exec.Command(t.suPath, "-c", "sh")
	} else {
		command = exec.Command("sh")
	}
	command.Stdin = strings.NewReader(content)
	combinedOutput, err := command.CombinedOutput()
	if err != nil {
		return E.Extend(err, string(combinedOutput))
	}
	return nil
}

func (t *TProxy) NewConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext) error {
	metadata.Destination = M.SocksaddrFromNet(conn.LocalAddr()).Unwrap()
	return t.newConnection(ctx, conn, metadata)
}

func (t *TProxy) NewPacket(ctx context.Context, conn N.PacketConn, buffer *buf.Buffer, oob []byte, metadata adapter.InboundContext) error {
	destination, err := redir.GetOriginalDestinationFromOOB(oob)
	if err != nil {
		return E.Cause(err, "get tproxy destination")
	}
	metadata.Destination = M.SocksaddrFromNetIP(destination).Unwrap()
	t.udpNat.NewContextPacket(ctx, metadata.Source.AddrPort(), buffer, adapter.UpstreamMetadata(metadata), func(natConn N.PacketConn) (context.Context, N.PacketWriter) {
		return adapter.WithContext(log.ContextWithNewID(ctx), &metadata), &tproxyPacketWriter{ctx: ctx, source: natConn, destination: metadata.Destination}
	})
	return nil
}

type tproxyPacketWriter struct {
	ctx         context.Context
	source      N.PacketConn
	destination M.Socksaddr
	conn        *net.UDPConn
}

func (w *tproxyPacketWriter) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	defer buffer.Release()
	conn := w.conn
	if w.destination == destination && conn != nil {
		_, err := conn.WriteToUDPAddrPort(buffer.Bytes(), M.AddrPortFromNet(w.source.LocalAddr()))
		if err != nil {
			w.conn = nil
		}
		return err
	}
	var listener net.ListenConfig
	listener.Control = control.Append(listener.Control, control.ReuseAddr())
	listener.Control = control.Append(listener.Control, redir.TProxyWriteBack())
	packetConn, err := listener.ListenPacket(w.ctx, "udp", destination.String())
	if err != nil {
		return err
	}
	udpConn := packetConn.(*net.UDPConn)
	if w.destination == destination {
		w.conn = udpConn
	} else {
		defer udpConn.Close()
	}
	return common.Error(udpConn.WriteToUDPAddrPort(buffer.Bytes(), M.AddrPortFromNet(w.source.LocalAddr())))
}

func (w *tproxyPacketWriter) Close() error {
	return common.Close(common.PtrOrNil(w.conn))
}
