// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package pktinfo

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"strconv"
	"testing"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// The Windows layouts are independent of the platform running the tests.
var layouts = []layout{4, 8}

func setLen(a layout, b []byte, n uint64) {
	if a == 4 {
		binary.LittleEndian.PutUint32(b, uint32(n))
	} else {
		binary.LittleEndian.PutUint64(b, n)
	}
}

func records(a layout, b []byte) (ms [][]byte, err error) {
	err = a.parse(b, func(level, typ int, data []byte) {
		ms = append(ms, append([]byte{byte(level), byte(typ)}, data...))
	})
	return ms, err
}

func TestLayout(t *testing.T) {
	// Literal little-endian fixtures: SIZE_T length, int32 level/type, payload.
	for _, tt := range []struct {
		a    layout
		want []byte
	}{
		{4, []byte{16, 0, 0, 0, 0, 0, 0, 0, 19, 0, 0, 0, 127, 0, 0, 1}},
		{8, []byte{20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 19, 0, 0, 0, 127, 0, 0, 1, 0, 0, 0, 0}},
	} {
		if got := tt.a.marshal(0, 19, []byte{127, 0, 0, 1}); !bytes.Equal(got, tt.want) {
			t.Errorf("layout %d: got %x; want %x", tt.a, got, tt.want)
		}
	}
	for _, a := range layouts {
		for n, want := range map[int]int{0: 0, 1: int(a), int(a): int(a), int(a) + 1: 2 * int(a), 20: 20 + 4*int(a/8)} {
			if got := a.space(n); got != a.headerLen()+want {
				t.Errorf("layout %d: space(%d) = %d; want %d", a, n, got, a.headerLen()+want)
			}
		}
	}
}

func TestParseLengths(t *testing.T) {
	for _, a := range layouts {
		t.Run(strconv.Itoa(int(a)), func(t *testing.T) {
			for _, size := range []int{a.headerLen(), a.space(8)} {
				for _, n := range []uint64{0, 1, uint64(a.headerLen() - 1), uint64(size + 1), 1<<32 - 1, 1<<64 - 1} {
					b := make([]byte, size)
					setLen(a, b, n)
					if _, err := records(a, b); !errors.Is(err, errInvalidLength) {
						t.Errorf("record length %d, buffer length %d: %v", n, size, err)
					}
				}
			}
			// Trailing bytes too short for a header are ignored.
			for n := 0; n < a.headerLen(); n++ {
				if ms, err := records(a, make([]byte, n)); err != nil || len(ms) != 0 {
					t.Errorf("%d header bytes: records=%x err=%v", n, ms, err)
				}
			}
			m := a.marshal(7, 19, []byte{42})
			// All final padding lengths, including omitted and nonzero
			// padding, are valid.
			for n := a.headerLen() + 1; n <= len(m); n++ {
				b := bytes.Clone(m[:n])
				for i := a.headerLen() + 1; i < n; i++ {
					b[i] = 0xff
				}
				if ms, err := records(a, b); err != nil || len(ms) != 1 || !bytes.Equal(ms[0], []byte{7, 19, 42}) {
					t.Errorf("padding length %d: records=%x err=%v", n, ms, err)
				}
			}
			if ms, err := records(a, append(bytes.Clone(m), 1)); err != nil || len(ms) != 1 {
				t.Errorf("trailing byte: records=%x err=%v", ms, err)
			}
			b := append(a.marshal(-1, -2, nil), a.marshal(41, 19, []byte{1, 2})...)
			ms, err := records(a, b)
			if err != nil || len(ms) != 2 || !bytes.Equal(ms[0], []byte{0xff, 0xfe}) || !bytes.Equal(ms[1], []byte{41, 19, 1, 2}) {
				t.Errorf("two records: records=%x err=%v", ms, err)
			}
		})
	}
}

func TestIPv4Controls(t *testing.T) {
	for _, a := range layouts {
		t.Run(strconv.Itoa(int(a)), func(t *testing.T) {
			cm := &ipv4.ControlMessage{Src: net.IPv4(127, 0, 0, 1), IfIndex: 7}
			b := marshalIPv4(a, cm)
			// Independent literal pktinfo payload, including a
			// little-endian ULONG index.
			want := a.marshal(0, 19, []byte{127, 0, 0, 1, 7, 0, 0, 0})
			if !bytes.Equal(b, want) {
				t.Fatalf("marshal: got %x; want %x", b, want)
			}
			got, err := parseIPv4(a, b, len(b), 0)
			if err != nil || !got.Dst.Equal(cm.Src) || len(got.Dst) != net.IPv4len || got.IfIndex != 7 || got.Src != nil {
				t.Fatalf("parse: %v err=%v", got, err)
			}
			for _, cm := range []*ipv4.ControlMessage{nil, {}, {TTL: 1}, {IfIndex: -1}, {Src: net.IPv6loopback}} {
				if b := marshalIPv4(a, cm); b != nil {
					t.Errorf("marshal %v: got %x; want nil", cm, b)
				}
			}
			if b := marshalIPv4(a, &ipv4.ControlMessage{IfIndex: 7}); !bytes.Equal(b, a.marshal(0, 19, []byte{0, 0, 0, 0, 7, 0, 0, 0})) {
				t.Errorf("marshal index: got %x", b)
			}
			// Short records are ignored, like other short controls, and
			// unknown levels and types (including type zero) are skipped.
			for n := 0; n < sizeofInPktinfo; n++ {
				b := a.marshal(0, 19, make([]byte, n))
				if cm, err := parseIPv4(a, b, len(b), 0); err != nil || cm == nil || cm.Dst != nil || cm.IfIndex != 0 {
					t.Errorf("packet info with %d payload bytes: cm=%v err=%v", n, cm, err)
				}
			}
			b = bytes.Join([][]byte{a.marshal(0, 0, []byte{42}), want, a.marshal(41, 19, make([]byte, 20))}, nil)
			if cm, err := parseIPv4(a, b, len(b), 0); err != nil || cm.IfIndex != 7 {
				t.Errorf("unknown records: cm=%v err=%v", cm, err)
			}
		})
	}
}

func TestIPv6Controls(t *testing.T) {
	ll := net.ParseIP("fe80::1")
	for _, a := range layouts {
		t.Run(strconv.Itoa(int(a)), func(t *testing.T) {
			cm := &ipv6.ControlMessage{Src: ll, IfIndex: 7, TrafficClass: 1}
			b := marshalIPv6(a, cm)
			want := a.marshal(41, 19, append(bytes.Clone(ll), 7, 0, 0, 0))
			if !bytes.Equal(b, want) {
				t.Fatalf("marshal: got %x; want %x", b, want)
			}
			got, err := parseIPv6(a, b, len(b), 0)
			if err != nil || !got.Dst.Equal(ll) || got.IfIndex != 7 || got.Src != nil {
				t.Fatalf("parse: %v err=%v", got, err)
			}
			for _, cm := range []*ipv6.ControlMessage{nil, {}, {HopLimit: 1}, {IfIndex: -1}, {Src: net.IPv4(127, 0, 0, 1)}} {
				if b := marshalIPv6(a, cm); b != nil {
					t.Errorf("marshal %v: got %x; want nil", cm, b)
				}
			}
			for n := 0; n < sizeofIn6Pktinfo; n++ {
				b := a.marshal(41, 19, make([]byte, n))
				if cm, err := parseIPv6(a, b, len(b), 0); err != nil || cm == nil || cm.Dst != nil || cm.IfIndex != 0 {
					t.Errorf("packet info with %d payload bytes: cm=%v err=%v", n, cm, err)
				}
			}
			b = bytes.Join([][]byte{a.marshal(41, 0, []byte{42}), want, a.marshal(0, 19, make([]byte, 8))}, nil)
			if cm, err := parseIPv6(a, b, len(b), 0); err != nil || cm.IfIndex != 7 || !cm.Dst.Equal(ll) {
				t.Errorf("unknown records: cm=%v err=%v", cm, err)
			}
		})
	}
}

func TestTruncatedControls(t *testing.T) {
	b := marshalIPv4(native, &ipv4.ControlMessage{Src: net.IPv4(127, 0, 0, 1), IfIndex: 7})
	for _, tc := range []struct {
		n, flags int
	}{
		{len(b), msgTrunc},
		{len(b), msgCtrunc},
		{len(b) + 1, 0},
		{-1, 0},
	} {
		if cm, err := parseIPv4(native, b, tc.n, tc.flags); cm != nil || !errors.Is(err, io.ErrShortBuffer) {
			t.Errorf("IPv4 %+v: cm=%v err=%v", tc, cm, err)
		}
		if cm, err := parseIPv6(native, b, tc.n, tc.flags); cm != nil || !errors.Is(err, io.ErrShortBuffer) {
			t.Errorf("IPv6 %+v: cm=%v err=%v", tc, cm, err)
		}
	}
	for _, b := range [][]byte{nil, {}} {
		if cm, err := parseIPv4(native, b, 0, 0); cm != nil || err != nil {
			t.Errorf("empty IPv4 controls: %v %v", cm, err)
		}
		if cm, err := parseIPv6(native, b, 0, 0); cm != nil || err != nil {
			t.Errorf("empty IPv6 controls: %v %v", cm, err)
		}
	}
	bad := bytes.Clone(b)
	setLen(native, bad, 1)
	if cm, err := parseIPv4(native, bad, len(bad), 0); cm != nil || !errors.Is(err, errInvalidLength) {
		t.Errorf("invalid IPv4 record: cm=%v err=%v", cm, err)
	}
	if cm, err := parseIPv6(native, bad, len(bad), 0); cm != nil || !errors.Is(err, errInvalidLength) {
		t.Errorf("invalid IPv6 record: cm=%v err=%v", cm, err)
	}
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// overflowIndexes returns interface indexes beyond a ULONG, which exist only
// on 64-bit platforms.
func overflowIndexes() []int {
	if strconv.IntSize != 64 {
		return nil
	}
	max := uint64(^uint32(0))
	return []int{int(max + 1), int(max + 2)}
}

func TestValidateIPv4(t *testing.T) {
	type test struct {
		name string
		cm   *ipv4.ControlMessage
		want error
	}
	tests := []test{
		{name: "nil"},
		{name: "empty", cm: &ipv4.ControlMessage{}},
		{name: "source", cm: &ipv4.ControlMessage{Src: net.IPv4(127, 0, 0, 1)}},
		{name: "source_and_index", cm: &ipv4.ControlMessage{Src: net.IP{127, 0, 0, 1}, IfIndex: 1}},
		{name: "mapped_source_and_index", cm: &ipv4.ControlMessage{Src: net.IPv4(127, 0, 0, 1), IfIndex: 1}},
		{name: "max_index", cm: &ipv4.ControlMessage{Src: net.IPv4(127, 0, 0, 1), IfIndex: int(min(uint64(^uint32(0)), math.MaxInt))}},
		{name: "index", cm: &ipv4.ControlMessage{IfIndex: 1}, want: errSourceRequired},
		{name: "empty_source_and_index", cm: &ipv4.ControlMessage{Src: net.IP{}, IfIndex: 1}, want: errSourceRequired},
		{name: "zero_source_and_index", cm: &ipv4.ControlMessage{Src: net.IP{0, 0, 0, 0}, IfIndex: 1}, want: errSourceRequired},
		{name: "mapped_zero_source_and_index", cm: &ipv4.ControlMessage{Src: net.IPv4zero, IfIndex: 1}, want: errSourceRequired},
		{name: "ipv6_source_and_index", cm: &ipv4.ControlMessage{Src: net.IPv6loopback, IfIndex: 1}, want: errSourceRequired},
		{name: "ipv6_source", cm: &ipv4.ControlMessage{Src: net.IPv6loopback}},
		{name: "negative_index", cm: &ipv4.ControlMessage{IfIndex: -1}},
		{name: "ttl", cm: &ipv4.ControlMessage{TTL: 1}},
		{name: "ttl_source_and_index", cm: &ipv4.ControlMessage{TTL: 1, Src: net.IPv4(127, 0, 0, 1), IfIndex: 1}},
	}
	for _, index := range overflowIndexes() {
		tests = append(tests, test{name: fmt.Sprintf("overflow_index_%d", index), cm: &ipv4.ControlMessage{Src: net.IPv4(127, 0, 0, 1), IfIndex: index}, want: errInvalidControl})
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := validateIPv4(tt.cm); err != tt.want {
				t.Fatalf("control %v: error = %q; want %q", tt.cm, errString(err), errString(tt.want))
			}
		})
	}
}

func TestValidateIPv6(t *testing.T) {
	type test struct {
		name string
		cm   *ipv6.ControlMessage
		want error
	}
	tests := []test{
		{name: "nil"},
		{name: "empty", cm: &ipv6.ControlMessage{}},
		{name: "source", cm: &ipv6.ControlMessage{Src: net.IPv6loopback}},
		{name: "source_and_index", cm: &ipv6.ControlMessage{Src: net.IPv6loopback, IfIndex: 1}},
		{name: "index", cm: &ipv6.ControlMessage{IfIndex: 1}, want: errSourceRequired},
		{name: "ipv4_source_and_index", cm: &ipv6.ControlMessage{Src: net.IPv4(127, 0, 0, 1), IfIndex: 1}, want: errSourceRequired},
		{name: "zero_source_and_index", cm: &ipv6.ControlMessage{Src: net.IPv6unspecified, IfIndex: 1}, want: errSourceRequired},
		{name: "zero_source", cm: &ipv6.ControlMessage{Src: net.IPv6unspecified}, want: errUnspecifiedSrc},
		{name: "ipv4_source", cm: &ipv6.ControlMessage{Src: net.IPv4(127, 0, 0, 1)}},
		{name: "negative_index", cm: &ipv6.ControlMessage{IfIndex: -1}},
		{name: "ipv4_next_hop", cm: &ipv6.ControlMessage{NextHop: net.IPv4(127, 0, 0, 1)}},
		{name: "traffic_class", cm: &ipv6.ControlMessage{TrafficClass: 1}, want: errNotImplemented},
		{name: "hop_limit", cm: &ipv6.ControlMessage{HopLimit: 1}, want: errNotImplemented},
		{name: "next_hop", cm: &ipv6.ControlMessage{NextHop: net.IPv6loopback}, want: errNotImplemented},
	}
	for _, index := range overflowIndexes() {
		tests = append(tests, test{name: fmt.Sprintf("overflow_index_%d", index), cm: &ipv6.ControlMessage{Src: net.IPv6loopback, IfIndex: index}, want: errInvalidControl})
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := validateIPv6(tt.cm); err != tt.want {
				t.Fatalf("control %v: error = %q; want %q", tt.cm, errString(err), errString(tt.want))
			}
		})
	}
}

func FuzzParseControls(f *testing.F) {
	f.Add([]byte{}, true)
	f.Add([]byte{1}, false)
	f.Add(marshalIPv4(8, &ipv4.ControlMessage{Src: net.IPv4(127, 0, 0, 1), IfIndex: 1}), true)
	f.Add(marshalIPv6(4, &ipv6.ControlMessage{Src: net.IPv6loopback, IfIndex: 1}), false)
	f.Fuzz(func(t *testing.T, b []byte, wide bool) {
		a := layout(4)
		if wide {
			a = 8
		}
		if ms, err := records(a, b); err == nil {
			for _, m := range ms {
				if len(m)-2 > len(b)-a.headerLen() {
					t.Fatalf("record %x longer than input %x", m, b)
				}
			}
		}
		if cm, err := parseIPv4(a, b, len(b), 0); err == nil && cm != nil && cm.Dst != nil && len(cm.Dst) != net.IPv4len {
			t.Fatalf("invalid IPv4 destination %v", cm.Dst)
		}
		if cm, err := parseIPv6(a, b, len(b), 0); err == nil && cm != nil && cm.Dst != nil && len(cm.Dst) != net.IPv6len {
			t.Fatalf("invalid IPv6 destination %v", cm.Dst)
		}
	})
}
