// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package pktinfo

import (
	"net"
	"runtime"
	"testing"
	"time"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// The same packet information behavior is expected on these platforms.
func skipUnsupported(t *testing.T) {
	t.Helper()
	switch runtime.GOOS {
	case "darwin", "linux", "windows":
	default:
		t.Skipf("not supported on %s", runtime.GOOS)
	}
}

// loopbackIndex returns the index of the interface with address ip.
func loopbackIndex(t *testing.T, ip net.IP) int {
	t.Helper()
	ifaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			t.Fatal(err)
		}
		for _, addr := range addrs {
			if a, _, err := net.ParseCIDR(addr.String()); err == nil && a.Equal(ip) {
				return iface.Index
			}
		}
	}
	t.Skipf("%v has no interface", ip)
	return 0
}

func listen(t *testing.T, network string, ip net.IP) *net.UDPConn {
	t.Helper()
	c, err := net.ListenUDP(network, &net.UDPAddr{IP: ip})
	if err != nil {
		t.Skipf("listen %s %v: %v", network, ip, err)
	}
	t.Cleanup(func() { c.Close() })
	c.SetDeadline(time.Now().Add(5 * time.Second))
	return c
}

func TestIPv4Loopback(t *testing.T) {
	skipUnsupported(t)
	lo := net.IPv4(127, 0, 0, 1).To4()
	index := loopbackIndex(t, lo)
	c := listen(t, "udp4", net.IPv4zero)
	peer := listen(t, "udp4", lo)
	p := NewIPv4PacketConn(c)
	if err := p.SetControlMessage(ipv4.FlagDst|ipv4.FlagInterface, true); err != nil {
		t.Fatal(err)
	}
	dst := &net.UDPAddr{IP: lo, Port: c.LocalAddr().(*net.UDPAddr).Port}
	if _, err := peer.WriteToUDP([]byte("scan"), dst); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 32)
	n, cm, from, err := p.ReadFrom(b)
	if err != nil || string(b[:n]) != "scan" || cm == nil || !cm.Dst.Equal(lo) || cm.IfIndex != index || !cm.Src.Equal(lo) || from.String() != peer.LocalAddr().String() {
		t.Fatalf("read: n=%d cm=%v from=%v err=%v; want src=dst=%v index=%d", n, cm, from, err, lo, index)
	}
	if n, err := p.WriteTo([]byte("reply"), &ipv4.ControlMessage{Src: cm.Dst, IfIndex: cm.IfIndex}, from); err != nil || n != 5 {
		t.Fatalf("write: n=%d err=%v", n, err)
	}
	n, source, err := peer.ReadFromUDP(b)
	if err != nil || string(b[:n]) != "reply" || !source.IP.Equal(lo) || source.Port != dst.Port {
		t.Fatalf("reply: n=%d from=%v err=%v; want %v", n, source, err, dst)
	}
}

func TestIPv6Loopback(t *testing.T) {
	skipUnsupported(t)
	lo := net.IPv6loopback
	index := loopbackIndex(t, lo)
	c := listen(t, "udp6", net.IPv6unspecified)
	peer := listen(t, "udp6", lo)
	p := NewIPv6PacketConn(c)
	if err := p.SetControlMessage(ipv6.FlagSrc|ipv6.FlagDst|ipv6.FlagInterface, true); err != nil {
		t.Fatal(err)
	}
	dst := &net.UDPAddr{IP: lo, Port: c.LocalAddr().(*net.UDPAddr).Port}
	if _, err := peer.WriteToUDP([]byte("scan"), dst); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 32)
	n, cm, from, err := p.ReadFrom(b)
	if err != nil || string(b[:n]) != "scan" || cm == nil || !cm.Dst.Equal(lo) || !cm.Src.Equal(lo) || cm.IfIndex != index {
		t.Fatalf("read: n=%d cm=%v from=%v err=%v; want src=dst=%v index=%d", n, cm, from, err, lo, index)
	}
	if n, err := p.WriteTo([]byte("reply"), &ipv6.ControlMessage{Src: cm.Dst, IfIndex: cm.IfIndex}, from); err != nil || n != 5 {
		t.Fatalf("write: n=%d err=%v", n, err)
	}
	n, source, err := peer.ReadFromUDP(b)
	if err != nil || string(b[:n]) != "reply" || !source.IP.Equal(lo) || source.Port != dst.Port {
		t.Fatalf("reply: n=%d from=%v err=%v; want %v", n, source, err, dst)
	}
}

func TestIPv4Connected(t *testing.T) {
	skipUnsupported(t)
	lo := net.IPv4(127, 0, 0, 1).To4()
	index := loopbackIndex(t, lo)
	peer := listen(t, "udp4", lo)
	c, err := net.DialUDP("udp4", nil, peer.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	p := NewIPv4PacketConn(c)
	cm := &ipv4.ControlMessage{Src: lo, IfIndex: index}
	// A connected socket accepts no address and, except on Darwin, where
	// sendmsg fails with EISCONN, its peer's address.
	dsts := []net.Addr{nil}
	if runtime.GOOS != "darwin" {
		dsts = append(dsts, peer.LocalAddr())
	}
	for _, dst := range dsts {
		if n, err := p.WriteTo([]byte("reply"), cm, dst); err != nil || n != 5 {
			t.Fatalf("write to %v: n=%d err=%v", dst, n, err)
		}
		b := make([]byte, 32)
		n, source, err := peer.ReadFromUDP(b)
		if err != nil || string(b[:n]) != "reply" || source.String() != c.LocalAddr().String() {
			t.Fatalf("reply: n=%d from=%v err=%v; want %v", n, source, err, c.LocalAddr())
		}
	}
}

func TestIPv4EnableDuringRead(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("x/net reserves control space when ReadFrom starts")
	}
	lo := net.IPv4(127, 0, 0, 1).To4()
	index := loopbackIndex(t, lo)
	c := listen(t, "udp4", net.IPv4zero)
	peer := listen(t, "udp4", lo)
	p := NewIPv4PacketConn(c)
	type result struct {
		n   int
		cm  *ipv4.ControlMessage
		err error
	}
	done := make(chan result, 1)
	go func() {
		b := make([]byte, 32)
		n, cm, _, err := p.ReadFrom(b)
		done <- result{n, cm, err}
	}()
	// Give the reader time to block in ReadFrom with controls disabled.
	time.Sleep(50 * time.Millisecond)
	if err := p.SetControlMessage(ipv4.FlagDst|ipv4.FlagInterface, true); err != nil {
		t.Fatal(err)
	}
	dst := &net.UDPAddr{IP: lo, Port: c.LocalAddr().(*net.UDPAddr).Port}
	if _, err := peer.WriteToUDP([]byte("scan"), dst); err != nil {
		t.Fatal(err)
	}
	r := <-done
	if r.err != nil || r.n != 4 || r.cm == nil || !r.cm.Dst.Equal(lo) || r.cm.IfIndex != index {
		t.Fatalf("read: n=%d cm=%v err=%v; want dst=%v index=%d", r.n, r.cm, r.err, lo, index)
	}
}
