// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package pktinfo

import (
	"errors"
	"fmt"
	"io"
	"net"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/windows"
)

// Negative array bounds make these ABI assertions compile checks as well as
// runtime tests, including when cross-compiling windows/386.
const (
	headerSize   = unsafe.Sizeof(windows.WSACMSGHDR{})
	levelOffset  = unsafe.Offsetof(windows.WSACMSGHDR{}.Level)
	typeOffset   = unsafe.Offsetof(windows.WSACMSGHDR{}.Type)
	pktinfoSize  = unsafe.Sizeof(windows.IN_PKTINFO{})
	pktinfo6Size = unsafe.Sizeof(windows.IN6_PKTINFO{})
	index6Offset = unsafe.Offsetof(windows.IN6_PKTINFO{}.Ifindex)
)

var (
	_ [headerSize - (uintptr(native) + 8)]byte
	_ [(uintptr(native) + 8) - headerSize]byte
	_ [levelOffset - uintptr(native)]byte
	_ [uintptr(native) - levelOffset]byte
	_ [typeOffset - uintptr(native) - 4]byte
	_ [uintptr(native) + 4 - typeOffset]byte
	_ [pktinfoSize - sizeofInPktinfo]byte
	_ [sizeofInPktinfo - pktinfoSize]byte
	_ [pktinfo6Size - sizeofIn6Pktinfo]byte
	_ [sizeofIn6Pktinfo - pktinfo6Size]byte
	_ [index6Offset - 16]byte
	_ [16 - index6Offset]byte
)

func TestWindowsABI(t *testing.T) {
	for _, tt := range []struct {
		name      string
		got, want int
	}{
		{"IPPROTO_IP", levelIP, windows.IPPROTO_IP},
		{"IPPROTO_IPV6", levelIPv6, windows.IPPROTO_IPV6},
		{"IP_PKTINFO", typePacketInfo, windows.IP_PKTINFO},
		{"IPV6_PKTINFO", typePacketInfo, windows.IPV6_PKTINFO},
		{"MSG_TRUNC", msgTrunc, windows.MSG_TRUNC},
		{"MSG_CTRUNC", msgCtrunc, windows.MSG_CTRUNC},
		{"WSACMSGHDR.Len", 0, int(unsafe.Offsetof(windows.WSACMSGHDR{}.Len))},
		{"IN_PKTINFO.Ifindex", 4, int(unsafe.Offsetof(windows.IN_PKTINFO{}.Ifindex))},
	} {
		if tt.got != tt.want {
			t.Errorf("%s = %d; want %d", tt.name, tt.got, tt.want)
		}
	}
	t.Logf("WSACMSGHDR: size=%d Level=%d Type=%d alignment=%d", headerSize, levelOffset, typeOffset, native)
}

func (c *sysConn) enabled(info uint) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.flags&info != 0
}

func ifaceIndex(t *testing.T, ip net.IP) int {
	t.Helper()
	index := loopbackIndex(t, ip)
	if index == 0 {
		t.Fatalf("%v has no interface", ip)
	}
	return index
}

func windowsIPv4(t *testing.T) (*net.UDPConn, *IPv4PacketConn, int) {
	t.Helper()
	index := ifaceIndex(t, net.IPv4(127, 0, 0, 1))
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	p := NewIPv4PacketConn(c)
	if err := p.SetControlMessage(ipv4.FlagDst|ipv4.FlagInterface, true); err != nil {
		t.Fatal(err)
	}
	if err := p.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	return c, p, index
}

func windowsIPv6(t *testing.T) (*net.UDPConn, *IPv6PacketConn, int) {
	t.Helper()
	index := ifaceIndex(t, net.IPv6loopback)
	c, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6unspecified})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	p := NewIPv6PacketConn(c)
	if err := p.SetControlMessage(ipv6.FlagSrc|ipv6.FlagDst|ipv6.FlagInterface, true); err != nil {
		t.Fatal(err)
	}
	if err := p.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	return c, p, index
}

func peerUDP(t *testing.T, network string, ip net.IP, zone string) *net.UDPConn {
	t.Helper()
	peer, err := net.ListenUDP(network, &net.UDPAddr{IP: ip, Zone: zone})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { peer.Close() })
	peer.SetDeadline(time.Now().Add(5 * time.Second))
	return peer
}

// unusedIndex returns an interface index that no interface has.
func unusedIndex(t *testing.T) int {
	t.Helper()
	ifaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	index := 1
	for _, iface := range ifaces {
		index = max(index, iface.Index+1)
	}
	return index
}

type writeTest struct {
	name    string
	wantErr error
	// stackErr is set if Windows rejects the control with an error matching
	// stackErr, which shows that WriteTo passes it to the stack. nil
	// matches any *net.OpError.
	stackErr  error
	stackFail bool
}

// checkWrite checks the result of a WriteTo of "reply" and, if it succeeded,
// that peer received it from src.
func checkWrite(t *testing.T, tt writeTest, n int, err error, peer *net.UDPConn, src *net.UDPAddr) {
	t.Helper()
	if tt.stackFail {
		if _, ok := err.(*net.OpError); n != 0 || !ok || tt.stackErr != nil && !errors.Is(err, tt.stackErr) {
			t.Fatalf("n=%d err=%v; want n=0 and *net.OpError wrapping %v", n, err, tt.stackErr)
		}
		return
	}
	if tt.wantErr != nil {
		if _, ok := err.(*net.OpError); n != 0 || !ok || !errors.Is(err, tt.wantErr) {
			t.Fatalf("n=%d err=%v; want n=0 and *net.OpError wrapping %q", n, err, tt.wantErr)
		}
		return
	}
	if err != nil || n != len("reply") {
		t.Fatalf("n=%d err=%v; want n=5 err=nil", n, err)
	}
	b := make([]byte, 32)
	n, source, err := peer.ReadFromUDP(b)
	if err != nil || string(b[:n]) != "reply" || !source.IP.Equal(src.IP) || source.Port != src.Port {
		t.Fatalf("reply: n=%d from=%v err=%v; want %v", n, source, err, src)
	}
}

func TestWindowsIPv4ControlMessage(t *testing.T) {
	c, p, index := windowsIPv4(t)
	lo := net.IPv4(127, 0, 0, 1)
	peer := peerUDP(t, "udp4", lo, "")
	dst := &net.UDPAddr{IP: lo, Port: c.LocalAddr().(*net.UDPAddr).Port}
	// Separately changing one flag must leave the shared socket option enabled.
	for _, flags := range []ipv4.ControlFlags{0, ipv4.FlagDst, ipv4.FlagInterface} {
		if flags != 0 {
			if err := p.SetControlMessage(flags, false); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := peer.WriteToUDP([]byte("scan"), dst); err != nil {
			t.Fatal(err)
		}
		b := make([]byte, 32)
		n, cm, from, err := p.ReadFrom(b)
		if err != nil || string(b[:n]) != "scan" || cm == nil || !cm.Dst.Equal(lo) || cm.IfIndex != index || !cm.Src.Equal(lo) {
			t.Fatalf("read: n=%d cm=%v from=%v err=%v; want src=dst=%v index=%d", n, cm, from, err, lo, index)
		}
		for _, tt := range []struct {
			writeTest
			cm *ipv4.ControlMessage
		}{
			{writeTest{name: "source_and_index"}, &ipv4.ControlMessage{Src: lo, IfIndex: index}},
			{writeTest{name: "source"}, &ipv4.ControlMessage{Src: lo}},
			{writeTest{name: "ttl"}, &ipv4.ControlMessage{TTL: 1}},
			{writeTest{name: "zero_source", stackFail: true}, &ipv4.ControlMessage{Src: net.IPv4zero}},
			{writeTest{name: "index", wantErr: errSourceRequired}, &ipv4.ControlMessage{IfIndex: index}},
			{writeTest{name: "zero_source_and_index", wantErr: errSourceRequired}, &ipv4.ControlMessage{Src: net.IPv4zero, IfIndex: index}},
			{writeTest{name: "nil"}, nil},
		} {
			t.Run(fmt.Sprintf("disabled_flags_%d/%s", flags, tt.name), func(t *testing.T) {
				deadline := time.Now().Add(5 * time.Second)
				p.SetDeadline(deadline)
				peer.SetDeadline(deadline)
				n, err := p.WriteTo([]byte("reply"), tt.cm, from)
				checkWrite(t, tt.writeTest, n, err, peer, dst)
			})
		}
		if flags != 0 {
			if err := p.SetControlMessage(flags, true); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := p.SetControlMessage(ipv4.FlagDst|ipv4.FlagInterface, false); err != nil {
		t.Fatal(err)
	}
	if _, err := peer.WriteToUDP([]byte("scan"), dst); err != nil {
		t.Fatal(err)
	}
	if _, cm, _, err := p.ReadFrom(make([]byte, 32)); err != nil || cm != nil {
		t.Fatalf("disabled controls: cm=%v err=%v", cm, err)
	}
}

func TestWindowsIPv6ControlMessage(t *testing.T) {
	c, p, index := windowsIPv6(t)
	lo := net.IPv6loopback
	peer := peerUDP(t, "udp6", lo, "")
	dst := &net.UDPAddr{IP: lo, Port: c.LocalAddr().(*net.UDPAddr).Port}
	unused := unusedIndex(t)
	for _, flags := range []ipv6.ControlFlags{0, ipv6.FlagDst, ipv6.FlagInterface} {
		if flags != 0 {
			if err := p.SetControlMessage(flags, false); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := peer.WriteToUDP([]byte("scan"), dst); err != nil {
			t.Fatal(err)
		}
		b := make([]byte, 32)
		n, cm, from, err := p.ReadFrom(b)
		if err != nil || string(b[:n]) != "scan" || cm == nil || !cm.Dst.Equal(lo) || cm.IfIndex != index || !cm.Src.Equal(lo) {
			t.Fatalf("read: n=%d cm=%v from=%v err=%v; want src=dst=%v index=%d", n, cm, from, err, lo, index)
		}
		for _, tt := range []struct {
			writeTest
			cm *ipv6.ControlMessage
		}{
			{writeTest{name: "source_and_index"}, &ipv6.ControlMessage{Src: lo, IfIndex: index}},
			{writeTest{name: "source"}, &ipv6.ControlMessage{Src: lo}},
			{writeTest{name: "ipv4_source"}, &ipv6.ControlMessage{Src: net.IPv4(127, 0, 0, 1)}},
			{writeTest{name: "unused_index", stackFail: true, stackErr: windows.WSAEINVAL}, &ipv6.ControlMessage{Src: lo, IfIndex: unused}},
			{writeTest{name: "index", wantErr: errSourceRequired}, &ipv6.ControlMessage{IfIndex: index}},
			{writeTest{name: "zero_source_and_index", wantErr: errSourceRequired}, &ipv6.ControlMessage{Src: net.IPv6unspecified, IfIndex: index}},
			{writeTest{name: "zero_source", wantErr: errUnspecifiedSrc}, &ipv6.ControlMessage{Src: net.IPv6unspecified}},
			{writeTest{name: "hop_limit", wantErr: errNotImplemented}, &ipv6.ControlMessage{HopLimit: 1}},
			{writeTest{name: "traffic_class", wantErr: errNotImplemented}, &ipv6.ControlMessage{TrafficClass: 1}},
			{writeTest{name: "next_hop", wantErr: errNotImplemented}, &ipv6.ControlMessage{NextHop: lo}},
			{writeTest{name: "nil"}, nil},
		} {
			t.Run(fmt.Sprintf("disabled_flags_%d/%s", flags, tt.name), func(t *testing.T) {
				deadline := time.Now().Add(5 * time.Second)
				p.SetDeadline(deadline)
				peer.SetDeadline(deadline)
				n, err := p.WriteTo([]byte("reply"), tt.cm, from)
				checkWrite(t, tt.writeTest, n, err, peer, dst)
			})
		}
		if flags != 0 {
			if err := p.SetControlMessage(flags, true); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := p.SetControlMessage(ipv6.FlagDst|ipv6.FlagInterface, false); err != nil {
		t.Fatal(err)
	}
	if _, err := peer.WriteToUDP([]byte("scan"), dst); err != nil {
		t.Fatal(err)
	}
	// FlagSrc alone does not request packet info.
	if _, cm, _, err := p.ReadFrom(make([]byte, 32)); err != nil || cm != nil {
		t.Fatalf("disabled controls: cm=%v err=%v", cm, err)
	}
}

func TestWindowsIPv6LinkLocalScope(t *testing.T) {
	ifaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	var ll *net.UDPAddr
	index := 0
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			t.Fatal(err)
		}
		for _, addr := range addrs {
			if ip, _, err := net.ParseCIDR(addr.String()); err == nil && ip.To4() == nil && ip.IsLinkLocalUnicast() {
				ll = &net.UDPAddr{IP: ip, Zone: iface.Name}
				index = iface.Index
			}
		}
		if ll != nil {
			break
		}
	}
	if ll == nil {
		t.Skip("no IPv6 link-local address")
	}
	c, p, _ := windowsIPv6(t)
	peer, err := net.ListenUDP("udp6", ll)
	if err != nil {
		t.Skipf("listen on %v: %v", ll, err)
	}
	defer peer.Close()
	peer.SetDeadline(time.Now().Add(5 * time.Second))
	dst := &net.UDPAddr{IP: ll.IP, Zone: ll.Zone, Port: c.LocalAddr().(*net.UDPAddr).Port}
	if _, err := peer.WriteToUDP([]byte("scan"), dst); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 32)
	n, cm, from, err := p.ReadFrom(b)
	if err != nil || string(b[:n]) != "scan" || cm == nil || !cm.Dst.Equal(ll.IP) || !cm.Src.Equal(ll.IP) || cm.IfIndex != index {
		t.Fatalf("read: n=%d cm=%v from=%v err=%v; want src=dst=%v index=%d", n, cm, from, err, ll, index)
	}
	n, err = p.WriteTo([]byte("reply"), &ipv6.ControlMessage{Src: ll.IP, IfIndex: index}, from)
	checkWrite(t, writeTest{}, n, err, peer, dst)
}

// packetConn is the common part of IPv4PacketConn and IPv6PacketConn.
type packetConn interface {
	SetReadDeadline(time.Time) error
	SetWriteDeadline(time.Time) error
	Close() error
}

func bothFamilies(t *testing.T, f func(t *testing.T, c *net.UDPConn, p packetConn, read func([]byte) (int, bool, error), write func([]byte, net.Addr) (int, error), lo net.IP)) {
	t.Run("ipv4", func(t *testing.T) {
		c, p, _ := windowsIPv4(t)
		read := func(b []byte) (int, bool, error) { n, cm, _, err := p.ReadFrom(b); return n, cm != nil, err }
		write := func(b []byte, dst net.Addr) (int, error) { return p.WriteTo(b, nil, dst) }
		f(t, c, p, read, write, net.IPv4(127, 0, 0, 1))
	})
	t.Run("ipv6", func(t *testing.T) {
		c, p, _ := windowsIPv6(t)
		read := func(b []byte) (int, bool, error) { n, cm, _, err := p.ReadFrom(b); return n, cm != nil, err }
		write := func(b []byte, dst net.Addr) (int, error) { return p.WriteTo(b, nil, dst) }
		f(t, c, p, read, write, net.IPv6loopback)
	})
}

func TestWindowsWriteDeadline(t *testing.T) {
	bothFamilies(t, func(t *testing.T, c *net.UDPConn, p packetConn, _ func([]byte) (int, bool, error), write func([]byte, net.Addr) (int, error), lo net.IP) {
		if err := p.SetWriteDeadline(time.Now()); err != nil {
			t.Fatal(err)
		}
		n, err := write([]byte("reply"), &net.UDPAddr{IP: lo, Port: c.LocalAddr().(*net.UDPAddr).Port})
		if ne, ok := err.(net.Error); !ok || !ne.Timeout() || n != 0 {
			t.Fatalf("write deadline: n=%d err=%v; want n=0 and timeout", n, err)
		}
	})
}

func TestWindowsDeadlineAndClose(t *testing.T) {
	bothFamilies(t, func(t *testing.T, _ *net.UDPConn, p packetConn, read func([]byte) (int, bool, error), _ func([]byte, net.Addr) (int, error), _ net.IP) {
		p.SetReadDeadline(time.Now())
		if _, cm, err := read(make([]byte, 32)); err == nil {
			t.Fatal("expired deadline succeeded")
		} else if ne, ok := err.(net.Error); !ok || !ne.Timeout() || cm {
			t.Fatalf("deadline: cm=%v err=%v", cm, err)
		}
		p.SetReadDeadline(time.Time{})
		done := make(chan error, 1)
		go func() { _, _, err := read(make([]byte, 32)); done <- err }()
		// Give the reader time to get stuck in ReadFrom.
		time.Sleep(50 * time.Millisecond)
		if err := p.Close(); err != nil {
			t.Fatal(err)
		}
		select {
		case err := <-done:
			if !errors.Is(err, net.ErrClosed) {
				t.Fatalf("close: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("Close did not unblock ReadFrom")
		}
	})
}

func TestWindowsTinyBuffers(t *testing.T) {
	for _, tt := range []struct {
		name    string
		network string
		lo      net.IP
		setup   func(*testing.T) (*net.UDPConn, func([]byte) (int, bool, net.Addr, error))
		readMsg func(*net.UDPConn, []byte, []byte) (bool, error)
	}{
		{"ipv4", "udp4", net.IPv4(127, 0, 0, 1),
			func(t *testing.T) (*net.UDPConn, func([]byte) (int, bool, net.Addr, error)) {
				c, p, _ := windowsIPv4(t)
				return c, func(b []byte) (int, bool, net.Addr, error) {
					n, cm, from, err := p.ReadFrom(b)
					return n, cm != nil, from, err
				}
			},
			func(c *net.UDPConn, b, oob []byte) (bool, error) {
				_, cm, _, err := readIPv4(c, b, oob)
				return cm != nil, err
			}},
		{"ipv6", "udp6", net.IPv6loopback,
			func(t *testing.T) (*net.UDPConn, func([]byte) (int, bool, net.Addr, error)) {
				c, p, _ := windowsIPv6(t)
				return c, func(b []byte) (int, bool, net.Addr, error) {
					n, cm, from, err := p.ReadFrom(b)
					return n, cm != nil, from, err
				}
			},
			func(c *net.UDPConn, b, oob []byte) (bool, error) {
				_, cm, _, err := readIPv6(c, b, oob)
				return cm != nil, err
			}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c, read := tt.setup(t)
			peer := peerUDP(t, tt.network, tt.lo, "")
			dst := &net.UDPAddr{IP: tt.lo, Port: c.LocalAddr().(*net.UDPAddr).Port}
			if _, err := peer.WriteToUDP(make([]byte, 32), dst); err != nil {
				t.Fatal(err)
			}
			n, cm, from, err := read(make([]byte, 1))
			if _, ok := err.(*net.OpError); n != 0 || cm || from != nil || !ok || !errors.Is(err, io.ErrShortBuffer) {
				t.Fatalf("tiny payload: n=%d cm=%v from=%v err=%v", n, cm, from, err)
			}
			// Exercise the actual stdlib transport with insufficient
			// ancillary space, using the same read path as ReadFrom.
			if _, err := peer.WriteToUDP([]byte("scan"), dst); err != nil {
				t.Fatal(err)
			}
			if cm, err := tt.readMsg(c, make([]byte, 32), make([]byte, 1)); cm || !errors.Is(err, io.ErrShortBuffer) {
				t.Fatalf("tiny controls: cm=%v err=%v", cm, err)
			}
			// Failed reads consume only that datagram; the socket remains
			// usable.
			if _, err := peer.WriteToUDP([]byte("ok"), dst); err != nil {
				t.Fatal(err)
			}
			if n, cm, _, err := read(make([]byte, 32)); err != nil || n != 2 || !cm {
				t.Fatalf("recovery: n=%d cm=%v err=%v", n, cm, err)
			}
		})
	}
}

func TestWindowsUnsupportedControls(t *testing.T) {
	_, p4, _ := windowsIPv4(t)
	for _, flags := range []ipv4.ControlFlags{ipv4.FlagTTL, ipv4.FlagSrc, ipv4.FlagTTL | ipv4.FlagDst, 1 << 20} {
		for _, on := range []bool{false, true} {
			if err := p4.SetControlMessage(flags, on); err != errNotImplemented {
				t.Errorf("IPv4 flags=%v on=%v: %v", flags, on, err)
			}
		}
	}
	_, p6, _ := windowsIPv6(t)
	for _, flags := range []ipv6.ControlFlags{ipv6.FlagTrafficClass, ipv6.FlagHopLimit, ipv6.FlagPathMTU, ipv6.FlagHopLimit | ipv6.FlagDst, 1 << 20} {
		for _, on := range []bool{false, true} {
			if err := p6.SetControlMessage(flags, on); err != errNotImplemented {
				t.Errorf("IPv6 flags=%v on=%v: %v", flags, on, err)
			}
		}
	}
	// A failed change leaves the enabled controls unchanged.
	if !p4.sys.enabled(ipv4Info) || !p6.sys.enabled(ipv6Info) {
		t.Error("controls disabled by unsupported flags")
	}
}

// wrappedUDPConn hides the *net.UDPConn type, as user wrappers do.
type wrappedUDPConn struct{ *net.UDPConn }

func TestWindowsWrappedConn(t *testing.T) {
	for _, tt := range []struct {
		network string
		lo      net.IP
	}{
		{"udp4", net.IPv4(127, 0, 0, 1)},
		{"udp6", net.IPv6loopback},
	} {
		t.Run(tt.network, func(t *testing.T) {
			c := peerUDP(t, tt.network, tt.lo, "")
			peer := peerUDP(t, tt.network, tt.lo, "")
			// Wrapped connections are the x/net connections: no controls,
			// but payload I/O still works.
			var setControl func() error
			var write func([]byte, net.Addr) (int, error)
			var read func([]byte) (int, bool, net.Addr, error)
			if tt.network == "udp4" {
				p := NewIPv4PacketConn(wrappedUDPConn{c})
				setControl = func() error { return p.SetControlMessage(ipv4.FlagDst, true) }
				write = func(b []byte, dst net.Addr) (int, error) { return p.WriteTo(b, &ipv4.ControlMessage{IfIndex: 1}, dst) }
				read = func(b []byte) (int, bool, net.Addr, error) {
					n, cm, from, err := p.ReadFrom(b)
					return n, cm != nil, from, err
				}
			} else {
				p := NewIPv6PacketConn(wrappedUDPConn{c})
				setControl = func() error { return p.SetControlMessage(ipv6.FlagDst, true) }
				write = func(b []byte, dst net.Addr) (int, error) { return p.WriteTo(b, &ipv6.ControlMessage{HopLimit: 1}, dst) }
				read = func(b []byte) (int, bool, net.Addr, error) {
					n, cm, from, err := p.ReadFrom(b)
					return n, cm != nil, from, err
				}
			}
			if err := setControl(); err == nil {
				t.Error("controls enabled")
			}
			if n, err := write([]byte("ping"), peer.LocalAddr()); err != nil || n != 4 {
				t.Fatalf("write: n=%d err=%v", n, err)
			}
			b := make([]byte, 32)
			if n, _, err := peer.ReadFromUDP(b); err != nil || string(b[:n]) != "ping" {
				t.Fatalf("peer read: %q %v", b[:n], err)
			}
			if _, err := peer.WriteToUDP([]byte("pong"), c.LocalAddr().(*net.UDPAddr)); err != nil {
				t.Fatal(err)
			}
			n, cm, from, err := read(b)
			if err != nil || string(b[:n]) != "pong" || cm || from.String() != peer.LocalAddr().String() {
				t.Fatalf("read: %q cm=%v from=%v err=%v", b[:n], cm, from, err)
			}
			if _, err := write([]byte("ping"), nil); err == nil {
				t.Error("write without address succeeded")
			}
		})
	}
}

func TestWindowsInvalidAddress(t *testing.T) {
	_, p4, _ := windowsIPv4(t)
	if _, err := p4.WriteTo([]byte("ping"), nil, &net.IPAddr{IP: net.IPv4(127, 0, 0, 1)}); !errors.Is(err, errInvalidConnType) {
		t.Errorf("IPv4: %v", err)
	}
	_, p6, _ := windowsIPv6(t)
	if _, err := p6.WriteTo([]byte("ping"), nil, &net.IPAddr{IP: net.IPv6loopback}); !errors.Is(err, errInvalidConnType) {
		t.Errorf("IPv6: %v", err)
	}
}
