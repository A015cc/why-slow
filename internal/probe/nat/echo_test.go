package nat

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/A015cc/why-slow/internal/netsys"
)

// TestFetchBypassesProxy is the regression test for the bug that motivated the
// whole nat probe. With every proxy environment variable pointed at a dead
// address, a client that honoured them would fail; the proxy-bypassing client
// must still reach the direct server. If this test ever fails, the tool is
// reporting the proxy's address as the user's public IP.
func TestFetchBypassesProxy(t *testing.T) {
	for _, kv := range [][2]string{
		{"HTTP_PROXY", "http://127.0.0.1:1"},
		{"HTTPS_PROXY", "http://127.0.0.1:1"},
		{"ALL_PROXY", "http://127.0.0.1:1"},
		{"http_proxy", "http://127.0.0.1:1"},
		{"https_proxy", "http://127.0.0.1:1"},
		{"all_proxy", "http://127.0.0.1:1"},
		{"NO_PROXY", ""},
	} {
		t.Setenv(kv[0], kv[1])
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "203.0.113.7\n")
	}))
	defer srv.Close()

	env := netsys.DefaultEnv()
	env.HTTP = netsys.DirectClient(2 * time.Second)
	p := New(env)

	ip, err := fetchIP(context.Background(), p.client(), endpoint{
		provider: "test", url: srv.URL, parse: parsePlainBody,
	})
	if err != nil {
		t.Fatalf("proxy-bypassing fetch failed: %v", err)
	}
	if !ip.Equal(net.ParseIP("203.0.113.7")) {
		t.Fatalf("ip = %v, want 203.0.113.7", ip)
	}
}

func TestParseCloudflareTrace(t *testing.T) {
	body := []byte("fl=abc\nh=1.1.1.1\nts=1\nip=198.51.100.4\nvisit_scheme=https\n")
	if got := parseCloudflareTrace(body); got != "198.51.100.4" {
		t.Fatalf("got %q", got)
	}
	if got := parseCloudflareTrace([]byte("no ip line here")); got != "" {
		t.Fatalf("expected empty, got %q", got)
	}
	if got := parseCloudflareTrace(nil); got != "" {
		t.Fatalf("nil: got %q", got)
	}
}

func TestParsePlainBody(t *testing.T) {
	cases := map[string]string{
		"198.51.100.4\n":         "198.51.100.4",
		"\n  2001:db8::1  \n":    "2001:db8::1",
		"banner text\nnot an ip": "",
		"":                       "",
	}
	for in, want := range cases {
		if got := parsePlainBody([]byte(in)); got != want {
			t.Errorf("parsePlainBody(%q) = %q, want %q", in, got, want)
		}
	}
}

// withV4Endpoints swaps the package endpoint list for the duration of a test, so
// agreement logic can be exercised against local servers with no real network.
func withV4Endpoints(t *testing.T, eps []endpoint) {
	t.Helper()
	old := v4Endpoints
	v4Endpoints = eps
	t.Cleanup(func() { v4Endpoints = old })
	oldV6 := v6Endpoints
	v6Endpoints = nil
	t.Cleanup(func() { v6Endpoints = oldV6 })
}

func echoServer(t *testing.T, body string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestLookupPublicAgreement(t *testing.T) {
	a := echoServer(t, "203.0.113.7\n")
	b := echoServer(t, "203.0.113.7\n")
	withV4Endpoints(t, []endpoint{
		{"a", a.URL, parsePlainBody},
		{"b", b.URL, parsePlainBody},
	})

	p := New(netsys.DefaultEnv())
	res := p.lookupPublic(context.Background())
	if res.v4 == nil || !res.v4.Equal(net.ParseIP("203.0.113.7")) {
		t.Fatalf("v4 = %v", res.v4)
	}
	if !res.agreement {
		t.Fatal("expected the two providers to agree")
	}
}

func TestLookupPublicDisagreement(t *testing.T) {
	a := echoServer(t, "203.0.113.7\n")
	b := echoServer(t, "198.51.100.9\n")
	withV4Endpoints(t, []endpoint{
		{"a", a.URL, parsePlainBody},
		{"b", b.URL, parsePlainBody},
	})

	res := New(netsys.DefaultEnv()).lookupPublic(context.Background())
	if res.agreement {
		t.Fatal("providers disagreed but agreement was reported true")
	}
}

func TestLookupPublicSingleProviderIsNotAgreement(t *testing.T) {
	a := echoServer(t, "203.0.113.7\n")
	withV4Endpoints(t, []endpoint{
		{"a", a.URL, parsePlainBody},
		{"dead", "http://127.0.0.1:1", parsePlainBody},
	})

	res := New(netsys.DefaultEnv()).lookupPublic(context.Background())
	if res.v4 == nil {
		t.Fatal("expected a surviving answer")
	}
	if res.agreement {
		t.Fatal("a single answer cannot constitute agreement")
	}
}

func TestLookupPublicAllFail(t *testing.T) {
	withV4Endpoints(t, []endpoint{
		{"dead1", "http://127.0.0.1:1", parsePlainBody},
		{"dead2", "http://127.0.0.1:1", parsePlainBody},
	})
	res := New(netsys.DefaultEnv()).lookupPublic(context.Background())
	if res.err == nil {
		t.Fatal("expected an error when no provider answers")
	}
	if res.v4 != nil {
		t.Fatalf("v4 = %v, want nil", res.v4)
	}
}
