package latency

import (
	"context"
	"net"
	"syscall"
	"testing"
	"time"

	"github.com/A015cc/why-slow/internal/model"
	"github.com/A015cc/why-slow/internal/netsys"
)

// stubConn satisfies the little of net.Conn that measure actually uses. Close is
// the only method a successful dial touches, so embedding a nil interface and
// overriding that one method is enough — and it makes an accidental call to any
// other method a loud panic rather than a silent pass.
type stubConn struct{ net.Conn }

func (stubConn) Close() error { return nil }

// scriptedDialer answers dials from a script, recording every address it was
// asked for so tests can assert what the probe actually dialled.
type scriptedDialer struct {
	calls  []string
	script []func(ctx context.Context) (net.Conn, error)
}

func (d *scriptedDialer) dial(ctx context.Context, network, address string) (net.Conn, error) {
	d.calls = append(d.calls, address)
	i := len(d.calls) - 1
	if i < len(d.script) {
		return d.script[i](ctx)
	}
	// Past the end of the script every attempt succeeds instantly, which keeps
	// tests that only care about a prefix from having to script the tail.
	return stubConn{}, nil
}

func okDial(ctx context.Context) (net.Conn, error) { return stubConn{}, nil }

func refusedDial(ctx context.Context) (net.Conn, error) {
	return nil, syscall.ECONNREFUSED
}

// blockingDial reproduces a filtered path: nothing answers until the deadline
// expires. This is the shape a dropped SYN takes from the client's side, and it
// is what must be classified as truncated rather than as a slow sample.
func blockingDial(ctx context.Context) (net.Conn, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func testEnv(d *scriptedDialer) *netsys.Env {
	return &netsys.Env{Dial: d.dial, Now: time.Now}
}

const subjectLoopback = "127.0.0.1"

// The load-bearing test of this package. A truncated sample is not a slow
// sample: if timed-out dials were pushed into the series, a batch of them would
// pile up at the timeout value and the cluster detector would dutifully report a
// high mode — the tool would be manufacturing the exact artefact it exists to
// find.
func TestTimeoutsAreCountedNotSampled(t *testing.T) {
	d := &scriptedDialer{script: []func(context.Context) (net.Conn, error){
		blockingDial, blockingDial, blockingDial,
	}}
	p := New(testEnv(d), "127.0.0.1:1", Options{N: 3, Timeout: 20 * time.Millisecond, Interval: 0})

	st := model.NewState()
	if err := p.Run(context.Background(), st); err != nil {
		t.Fatalf("Run: %v", err)
	}

	if got := st.Series(probeName, KeyConnect, subjectLoopback); got != nil {
		t.Errorf("tcp.connect series = %v, want nil: truncated samples must not be recorded as timings", got)
	}
	if got, _ := st.Num(probeName, KeyTruncated, subjectLoopback); got != 3 {
		t.Errorf("truncated = %v, want 3", got)
	}
	if got, _ := st.Num(probeName, KeyAttempts, subjectLoopback); got != 3 {
		t.Errorf("attempts = %v, want 3", got)
	}
}

// A refused connection and a silent one are different diagnoses — "the service
// is down" versus "something is eating SYNs" — so they must not collapse into
// one error counter.
func TestRefusedAndTimeoutAreClassifiedApart(t *testing.T) {
	d := &scriptedDialer{script: []func(context.Context) (net.Conn, error){
		okDial, refusedDial, blockingDial, okDial,
	}}
	p := New(testEnv(d), "127.0.0.1:1", Options{N: 4, Timeout: 20 * time.Millisecond, Interval: 0})

	st := model.NewState()
	if err := p.Run(context.Background(), st); err != nil {
		t.Fatalf("Run: %v", err)
	}

	series := st.Series(probeName, KeyConnect, subjectLoopback)
	if len(series) != 2 {
		t.Errorf("series length = %d, want 2 (only the completed handshakes)", len(series))
	}
	if got, _ := st.Num(probeName, KeyRefused, subjectLoopback); got != 1 {
		t.Errorf("refused = %v, want 1", got)
	}
	if got, _ := st.Num(probeName, KeyTruncated, subjectLoopback); got != 1 {
		t.Errorf("truncated = %v, want 1", got)
	}
	if got, _ := st.Num(probeName, KeyAttempts, subjectLoopback); got != 4 {
		t.Errorf("attempts = %v, want 4", got)
	}
}

// The handshake must be measured against a resolved address, never a hostname:
// handing net.Dialer a name folds the resolver's latency into the connect time,
// which is the blending this tool exists to undo.
func TestDialsResolvedLiteralNotHostname(t *testing.T) {
	d := &scriptedDialer{script: []func(context.Context) (net.Conn, error){okDial}}
	p := New(testEnv(d), "127.0.0.1:8443", Options{N: 1, Timeout: time.Second, Interval: 0})

	st := model.NewState()
	if err := p.Run(context.Background(), st); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(d.calls) != 1 {
		t.Fatalf("dial calls = %v, want exactly 1", d.calls)
	}
	if d.calls[0] != "127.0.0.1:8443" {
		t.Errorf("dialled %q, want the IP literal %q", d.calls[0], "127.0.0.1:8443")
	}
	if got := st.Series(probeName, KeyConnect, subjectLoopback); len(got) != 1 {
		t.Errorf("series = %v, want one sample", got)
	}
	// An IP literal involves no resolver, so a lookup time would be a fiction.
	if _, ok := st.One(probeName, KeyDNSLookup, subjectLoopback); ok {
		t.Error("dns.lookup_ms recorded for an IP literal; there was no lookup to time")
	}
}

// The order inside an A/B pair must actually follow the coin, otherwise the
// second measurement of every pair inherits the first one's hangover and the
// interleaving buys nothing.
func TestCompareOrderFollowsTheCoin(t *testing.T) {
	d := &scriptedDialer{}
	flip := false
	p := New(testEnv(d), "127.0.0.1:1", Options{
		N: 1, Pairs: 4, Timeout: time.Second, Interval: 0,
		Compare: "127.0.0.2:2",
		Coin:    func() bool { flip = !flip; return flip },
	})

	st := model.NewState()
	if err := p.Run(context.Background(), st); err != nil {
		t.Fatalf("Run: %v", err)
	}

	want := []string{
		"127.0.0.1:1", // main target sample (N=1)
		"127.0.0.1:1", "127.0.0.2:2",
		"127.0.0.2:2", "127.0.0.1:1",
		"127.0.0.1:1", "127.0.0.2:2",
		"127.0.0.2:2", "127.0.0.1:1",
	}
	if len(d.calls) != len(want) {
		t.Fatalf("dialled %v, want %v", d.calls, want)
	}
	for i := range want {
		if d.calls[i] != want[i] {
			t.Fatalf("dial order = %v, want %v", d.calls, want)
		}
	}
}

// A pair with an incomplete side tells us nothing about the difference between
// the targets, and a truncated member would fabricate a delta near the timeout.
// Such pairs are dropped, and the drop count stays visible.
func TestCompareDropsIncompletePairs(t *testing.T) {
	d := &scriptedDialer{}
	// Main target answers; the compare target never does.
	env := &netsys.Env{
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d.calls = append(d.calls, address)
			if address == "127.0.0.2:2" {
				<-ctx.Done()
				return nil, ctx.Err()
			}
			return stubConn{}, nil
		},
		Now: time.Now,
	}
	p := New(env, "127.0.0.1:1", Options{
		N: 1, Pairs: 3, Timeout: 20 * time.Millisecond, Interval: 0,
		Compare: "127.0.0.2:2",
		Coin:    func() bool { return true },
	})

	st := model.NewState()
	if err := p.Run(context.Background(), st); err != nil {
		t.Fatalf("Run: %v", err)
	}

	const subject = "127.0.0.1:1 vs 127.0.0.2:2"
	if got, _ := st.Num(probeName, KeyABPairs, subject); got != 0 {
		t.Errorf("pairs = %v, want 0 (every pair had an incomplete side)", got)
	}
	if got, _ := st.Num(probeName, KeyABSkipped, subject); got != 3 {
		t.Errorf("skipped = %v, want 3", got)
	}
	if got := st.Series(probeName, KeyABDelta, subject); got != nil {
		t.Errorf("delta series = %v, want nil", got)
	}
}

// A name the requested family has no address for must fail loudly rather than
// silently measuring something else.
func TestFamilyFiltering(t *testing.T) {
	v4 := net.ParseIP("1.2.3.4")
	v6 := net.ParseIP("2606:4700:4700::1111")

	if got := filterFamily([]net.IP{v4, v6}, "4"); len(got) != 1 || got[0].String() != "1.2.3.4" {
		t.Errorf("family 4 -> %v", got)
	}
	if got := filterFamily([]net.IP{v4, v6}, "6"); len(got) != 1 || got[0].String() != v6.String() {
		t.Errorf("family 6 -> %v", got)
	}
	if got := filterFamily([]net.IP{v4, v6}, "auto"); len(got) != 2 {
		t.Errorf("family auto -> %v, want both", got)
	}

	// Default preference is IPv4 even when the name has both: the failures this
	// tool was written for are IPv4 failures, and a dual-stack host often takes a
	// completely different (cleaner) route over v6, which would report a healthy
	// number for a v4 problem.
	if got := pickTargets([]net.IP{v6, v4}, Options{}); len(got) != 1 || got[0].String() != "1.2.3.4" {
		t.Errorf("default pick -> %v, want the IPv4 address", got)
	}
	if got := pickTargets([]net.IP{v6, v4}, Options{Family: "6"}); len(got) != 1 || got[0].String() != v6.String() {
		t.Errorf("family 6 pick -> %v", got)
	}
	if got := pickTargets([]net.IP{v4, v6}, Options{AllIPs: true}); len(got) != 2 {
		t.Errorf("--all-ips -> %v, want both", got)
	}
	if got := pickTargets([]net.IP{v6}, Options{}); len(got) != 1 || got[0].String() != v6.String() {
		t.Errorf("v6-only name -> %v, want the v6 address rather than nothing", got)
	}
}

// Defaults are part of the method, not cosmetics: a 1-2s timeout would truncate
// the very samples the detector looks for.
func TestDefaultTimeoutIsLongEnoughForTheFirstRungs(t *testing.T) {
	d := DefaultOptions()
	if d.Timeout < 5*time.Second {
		t.Errorf("default timeout = %v; it must outlast the +1s and +3s rungs plus a slow baseline", d.Timeout)
	}
	if d.N < 20 {
		t.Errorf("default N = %d; the detector refuses to draw conclusions below 20 samples", d.N)
	}
	if d.Interval <= 0 {
		t.Errorf("default interval = %v; back-to-back dials can trip SYN flood protection and fake a high mode", d.Interval)
	}
}

func TestEmptyTargetFails(t *testing.T) {
	p := New(testEnv(&scriptedDialer{}), "   ", DefaultOptions())
	if err := p.Run(context.Background(), model.NewState()); err == nil {
		t.Error("Run on an empty target returned nil, want an error")
	}
}
