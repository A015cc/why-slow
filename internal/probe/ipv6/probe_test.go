package ipv6

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/A015cc/why-slow/internal/model"
	"github.com/A015cc/why-slow/internal/netsys"
)

// ipnet preserves the address as written rather than masking it to the network
// base, so the test fixtures carry the host bits they claim.
func ipnet(cidr string) net.Addr {
	ip, n, err := net.ParseCIDR(cidr)
	if err != nil {
		panic(err)
	}
	return &net.IPNet{IP: ip, Mask: n.Mask}
}

func TestV6OfFiltersIPv4AndNonIPAddrs(t *testing.T) {
	ifc := netsys.Iface{
		Name: "eth0",
		Addrs: []net.Addr{
			ipnet("192.168.1.10/24"),
			ipnet("2001:db8::1/64"),
			ipnet("fe80::1/64"),
			&net.TCPAddr{IP: net.ParseIP("10.0.0.1")}, // not an *net.IPNet; ignored
			nil,
		},
	}
	got := v6Of(ifc)
	if len(got) != 2 {
		t.Fatalf("got %d v6 addrs, want 2", len(got))
	}
	if !got[0].Equal(net.ParseIP("2001:db8::1")) || !got[1].Equal(net.ParseIP("fe80::1")) {
		t.Fatalf("unexpected addrs: %v", got)
	}
}

func TestV6OfEmptyNoPanic(t *testing.T) {
	if got := v6Of(netsys.Iface{}); len(got) != 0 {
		t.Fatalf("got %v", got)
	}
	if got := v6Of(netsys.Iface{Addrs: []net.Addr{nil, &net.TCPAddr{}}}); len(got) != 0 {
		t.Fatalf("got %v", got)
	}
}

func TestCountGlobal(t *testing.T) {
	ips := []net.IP{
		net.ParseIP("2001:db8::1"), // global
		net.ParseIP("2606:4700:4700::1111"),
		net.ParseIP("fd00::1"),     // ULA
		net.ParseIP("fe80::1"),     // link-local
		net.ParseIP("::1"),         // loopback
		net.ParseIP("2002::1"),     // 6to4, inside 2000::/3 so counted as global
		net.ParseIP("192.168.1.1"), // v4, not global v6
	}
	if got := countGlobal(ips); got != 3 {
		t.Fatalf("countGlobal = %d, want 3", got)
	}
}

func TestJoinClasses(t *testing.T) {
	got := joinClasses([]net.IP{net.ParseIP("2001:db8::1"), net.ParseIP("fe80::1"), nil})
	if !strings.Contains(got, "global unicast IPv6") || !strings.Contains(got, "link-local") {
		t.Fatalf("joinClasses = %q", got)
	}
	if got := joinClasses(nil); got != "" {
		t.Fatalf("joinClasses(nil) = %q", got)
	}
}

func TestParseProcNetIPv6Route(t *testing.T) {
	withDefault := "00000000000000000000000000000000 00 00000000000000000000000000000000 00 00000000 00000001 00000000 00000000 eth0\n" +
		"20010db8000000000000000000000001 80 00000000000000000000000000000000 00 00000000 00000001 00000000 00000000 eth0\n"
	has, ok := parseProcNetIPv6Route(strings.NewReader(withDefault))
	if !has || !ok {
		t.Fatalf("withDefault: has=%v ok=%v", has, ok)
	}

	noDefault := "20010db8000000000000000000000001 80 00000000000000000000000000000000 00 00000000 00000001 00000000 00000000 eth0\n"
	has, ok = parseProcNetIPv6Route(strings.NewReader(noDefault))
	if has || !ok {
		t.Fatalf("noDefault: has=%v ok=%v", has, ok)
	}

	if _, ok := parseProcNetIPv6Route(strings.NewReader("")); ok {
		t.Fatal("empty input should report ok=false")
	}
}

func TestParseProcNetIPv6RouteOddNoPanic(t *testing.T) {
	for _, in := range []string{"", "\n", "x", "abc def", "0000 00", strings.Repeat("f", 40) + " 00"} {
		_, _ = parseProcNetIPv6Route(strings.NewReader(in))
	}
}

func TestNewDefaultsTarget(t *testing.T) {
	if p := New(nil, ""); p.target != defaultTarget {
		t.Fatalf("empty target = %q, want %q", p.target, defaultTarget)
	}
	if p := New(nil, "  "); p.target != defaultTarget {
		t.Fatalf("blank target = %q, want %q", p.target, defaultTarget)
	}
	if p := New(nil, "[::1]:80"); p.target != "[::1]:80" {
		t.Fatalf("explicit target = %q", p.target)
	}
	if New(nil, "").Name() != "ipv6" {
		t.Fatal("wrong probe name")
	}
}

type fakeConn struct{}

func (fakeConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (fakeConn) Write(b []byte) (int, error)      { return len(b), nil }
func (fakeConn) Close() error                     { return nil }
func (fakeConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (fakeConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (fakeConn) SetDeadline(time.Time) error      { return nil }
func (fakeConn) SetReadDeadline(time.Time) error  { return nil }
func (fakeConn) SetWriteDeadline(time.Time) error { return nil }

func testEnv(dial netsys.DialFunc, ifaces []netsys.Iface) *netsys.Env {
	return &netsys.Env{
		Dial:   dial,
		Ifaces: func() ([]netsys.Iface, error) { return ifaces, nil },
	}
}

func TestRunRecordsInventoryAndReachability(t *testing.T) {
	ifaces := []netsys.Iface{{
		Name: "eth0",
		Addrs: []net.Addr{
			ipnet("2001:db8::1/64"),
			ipnet("fe80::1/64"),
		},
	}}
	env := testEnv(func(context.Context, string, string) (net.Conn, error) { return fakeConn{}, nil }, ifaces)

	st := model.NewState()
	if err := New(env, "").Run(context.Background(), st); err != nil {
		t.Fatal(err)
	}

	if v, ok := st.TextOf("ipv6", "ipv6.any_global", "ipv6"); !ok || v != "true" {
		t.Fatalf("any_global = %q ok=%v", v, ok)
	}
	if v, ok := st.TextOf("ipv6", "ipv6.reachable", "ipv6"); !ok || v != "true" {
		t.Fatalf("reachable = %q ok=%v", v, ok)
	}
	if st.Has("ipv6", "ipv6.error", "ipv6") {
		t.Fatal("unexpected error observation on a successful dial")
	}
	if n, ok := st.Num("ipv6", "v6.global_count", "eth0"); !ok || n != 1 {
		t.Fatalf("global_count = %v ok=%v", n, ok)
	}
	if v, ok := st.TextOf("ipv6", "v6.classes", "eth0"); !ok || !strings.Contains(v, "global unicast IPv6") {
		t.Fatalf("classes = %q", v)
	}
}

func TestRunRecordsDialFailure(t *testing.T) {
	env := testEnv(func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("network is unreachable")
	}, nil)

	st := model.NewState()
	if err := New(env, "[2606:4700:4700::1111]:443").Run(context.Background(), st); err != nil {
		t.Fatal(err)
	}
	if v, ok := st.TextOf("ipv6", "ipv6.reachable", "ipv6"); !ok || v != "false" {
		t.Fatalf("reachable = %q ok=%v", v, ok)
	}
	if v, ok := st.TextOf("ipv6", "ipv6.error", "ipv6"); !ok || v == "" {
		t.Fatalf("error = %q ok=%v", v, ok)
	}
	if v, ok := st.TextOf("ipv6", "ipv6.any_global", "ipv6"); !ok || v != "false" {
		t.Fatalf("any_global = %q ok=%v", v, ok)
	}
}

func TestRunNoIfacesNoPanic(t *testing.T) {
	env := testEnv(func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("nope")
	}, nil)
	st := model.NewState()
	if err := New(env, "").Run(context.Background(), st); err != nil {
		t.Fatal(err)
	}
}
