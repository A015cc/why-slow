package path

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func TestNormalizeTarget(t *testing.T) {
	cases := []struct {
		in, host, port string
	}{
		{"example.com", "example.com", "443"},
		{"example.com:8080", "example.com", "8080"},
		{"1.1.1.1", "1.1.1.1", "443"},
		{"1.1.1.1:53", "1.1.1.1", "53"},
		{"[2606:4700:4700::1111]", "2606:4700:4700::1111", "443"},
		{"[2606:4700:4700::1111]:443", "2606:4700:4700::1111", "443"},
		{"https://example.com/path?q=1", "example.com", "443"},
		{"  example.com  ", "example.com", "443"},
		{"", "", "443"},
		{"   ", "", "443"},
		// Odd but must not panic; treated as an opaque host.
		{":::", ":::", "443"},
		{"2001:db8::1", "2001:db8::1", "443"},
	}
	for _, c := range cases {
		host, port := normalizeTarget(c.in)
		if host != c.host || port != c.port {
			t.Errorf("normalizeTarget(%q) = (%q,%q), want (%q,%q)", c.in, host, port, c.host, c.port)
		}
	}
}

func TestBoolText(t *testing.T) {
	if boolText(true) != "true" || boolText(false) != "false" {
		t.Fatalf("boolText produced %q/%q", boolText(true), boolText(false))
	}
}

func TestKindOf(t *testing.T) {
	if got := kindOf(false, ""); got != "physical" {
		t.Errorf("physical: got %q", got)
	}
	if got := kindOf(true, "WireGuard tunnel"); got != "WireGuard tunnel" {
		t.Errorf("virtual kind: got %q", got)
	}
	if got := kindOf(true, ""); got != "virtual" {
		t.Errorf("virtual without kind: got %q", got)
	}
}

func TestJoinAddrsSkipsNilsAndEmpty(t *testing.T) {
	n := &net.IPNet{IP: net.ParseIP("192.168.1.10"), Mask: net.CIDRMask(24, 32)}
	var nilAddr net.Addr
	got := joinAddrs([]net.Addr{nilAddr, n, nil})
	if got != "192.168.1.10/24" {
		t.Fatalf("joinAddrs = %q", got)
	}
	if got := joinAddrs(nil); got != "" {
		t.Fatalf("joinAddrs(nil) = %q, want empty", got)
	}
}

func TestJoinIPsSkipsNils(t *testing.T) {
	got := joinIPs([]net.IP{nil, net.ParseIP("10.0.0.1"), net.ParseIP("fe80::1")})
	if got != "10.0.0.1,fe80::1" {
		t.Fatalf("joinIPs = %q", got)
	}
}

func TestParseProcNetRoute(t *testing.T) {
	table := strings.Join([]string{
		"Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT",
		"eth0\t00000000\t0102A8C0\t0003\t0\t0\t0\t00000000\t0\t0\t0",
		"eth0\t0002A8C0\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0",
	}, "\n")
	gw, ok := parseProcNetRoute(strings.NewReader(table))
	if !ok {
		t.Fatal("expected a default gateway")
	}
	if gw.String() != "192.168.2.1" {
		t.Fatalf("gateway = %s, want 192.168.2.1", gw)
	}
}

func TestParseProcNetRouteNoDefault(t *testing.T) {
	table := "eth0\t0002A8C0\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0\n"
	if gw, ok := parseProcNetRoute(strings.NewReader(table)); ok {
		t.Fatalf("expected no default route, got %v", gw)
	}
}

func TestParseProcNetRouteOddInputNoPanic(t *testing.T) {
	for _, in := range []string{
		"", "garbage", "\n\n", "a b c", "Iface Destination Gateway",
		"eth0 zzzz 00000000 0000 0 0 0 00000000 0 0 0",
	} {
		_, _ = parseProcNetRoute(strings.NewReader(in))
	}
}

// fakeConn is a net.Conn whose LocalAddr can change after the first Write, which
// is exactly the Windows deferral behaviour the fallback exists for.
type fakeConn struct {
	local      *net.UDPAddr
	afterWrite *net.UDPAddr
	writes     int
}

func (c *fakeConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (c *fakeConn) Close() error                     { return nil }
func (c *fakeConn) LocalAddr() net.Addr              { return c.local }
func (c *fakeConn) RemoteAddr() net.Addr             { return &net.UDPAddr{} }
func (c *fakeConn) SetDeadline(time.Time) error      { return nil }
func (c *fakeConn) SetReadDeadline(time.Time) error  { return nil }
func (c *fakeConn) SetWriteDeadline(time.Time) error { return nil }
func (c *fakeConn) Write(b []byte) (int, error) {
	c.writes++
	if c.afterWrite != nil {
		c.local = c.afterWrite
	}
	return len(b), nil
}

func TestEgressSourceUsesLocalAddrWhenSpecified(t *testing.T) {
	conn := &fakeConn{local: &net.UDPAddr{IP: net.ParseIP("10.1.2.3"), Port: 40000}}
	dial := func(context.Context, string, string) (net.Conn, error) { return conn, nil }
	ip, err := egressSource(context.Background(), dial, net.ParseIP("1.1.1.1"), "443")
	if err != nil {
		t.Fatal(err)
	}
	if !ip.Equal(net.ParseIP("10.1.2.3")) {
		t.Fatalf("ip = %v", ip)
	}
	if conn.writes != 0 {
		t.Fatalf("expected no send when LocalAddr is already specified, got %d", conn.writes)
	}
}

func TestEgressSourceSendsWhenUnspecified(t *testing.T) {
	conn := &fakeConn{
		local:      &net.UDPAddr{IP: net.IPv4zero, Port: 0},
		afterWrite: &net.UDPAddr{IP: net.ParseIP("192.168.1.5"), Port: 50000},
	}
	dial := func(context.Context, string, string) (net.Conn, error) { return conn, nil }
	ip, err := egressSource(context.Background(), dial, net.ParseIP("1.1.1.1"), "443")
	if err != nil {
		t.Fatal(err)
	}
	if !ip.Equal(net.ParseIP("192.168.1.5")) {
		t.Fatalf("ip = %v", ip)
	}
	if conn.writes != 1 {
		t.Fatalf("expected exactly one fallback send, got %d", conn.writes)
	}
}

func TestEgressSourceNilRemoteIP(t *testing.T) {
	dial := func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("should not be called")
	}
	if _, err := egressSource(context.Background(), dial, nil, "443"); err == nil {
		t.Fatal("expected an error for a nil remote IP")
	}
}

func TestEgressSourceNeverCommits(t *testing.T) {
	conn := &fakeConn{local: &net.UDPAddr{IP: net.IPv4zero, Port: 0}}
	dial := func(context.Context, string, string) (net.Conn, error) { return conn, nil }
	if _, err := egressSource(context.Background(), dial, net.ParseIP("1.1.1.1"), "443"); !errors.Is(err, errNoEgressSource) {
		t.Fatalf("err = %v, want errNoEgressSource", err)
	}
}

func TestAddrIP(t *testing.T) {
	if got := addrIP(&net.UDPAddr{IP: net.ParseIP("10.0.0.1")}); !got.Equal(net.ParseIP("10.0.0.1")) {
		t.Errorf("udp: %v", got)
	}
	var u *net.UDPAddr
	if addrIP(u) != nil {
		t.Error("typed nil UDPAddr should yield nil")
	}
	if addrIP(nil) != nil {
		t.Error("nil addr should yield nil")
	}
	// A fake address routes through the string fallback without panicking.
	if got := addrIP(fakeAddr{"1.2.3.4"}); !got.Equal(net.ParseIP("1.2.3.4")) {
		t.Errorf("fallback: %v", got)
	}
}

type fakeAddr struct{ s string }

func (a fakeAddr) Network() string { return "fake" }
func (a fakeAddr) String() string  { return a.s }

// TestDefaultGatewayNoPanic guards the platform entry point: on this (Windows)
// machine it must simply report unknown, never panic.
func TestDefaultGatewayNoPanic(t *testing.T) {
	gw, ok := DefaultGateway()
	if ok && gw == nil {
		t.Fatal("ok=true with a nil gateway")
	}
}
