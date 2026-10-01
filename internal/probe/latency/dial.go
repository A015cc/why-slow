package latency

import (
	"context"
	"errors"
	"net"
	"os"
	"syscall"
	"time"

	"github.com/A015cc/why-slow/internal/netsys"
)

// outcome is what a single dial attempt produced. Keeping these apart is not
// bookkeeping: ECONNREFUSED means a host answered and a port was closed, while a
// timeout means nothing answered at all. Collapsing both into "err != nil" would
// merge "the service is down" with "something on the path is eating SYNs", which
// are the two diagnoses this tool exists to tell apart.
type outcome int

const (
	outcomeOK outcome = iota
	// outcomeRefused is a RST: the peer is reachable, the port is not listening.
	outcomeRefused
	// outcomeTimeout is silence until the deadline: filtered, dropped, or a
	// blackhole. This is the shape a retransmission ladder ends in when it runs
	// past the dial timeout.
	outcomeTimeout
	// outcomeOther is anything else — DNS failures on a literal, local resource
	// exhaustion, a cancelled context.
	outcomeOther
)

// sample is one measured dial attempt.
type sample struct {
	ms      float64
	outcome outcome
	err     error
}

// measure performs one timed TCP handshake to a resolved IP.
//
// It takes an IP and a port rather than a host:port on purpose. Handing a
// hostname to net.Dialer would fold name resolution into the measured interval,
// and a slow resolver is a different problem with a different fix than a lossy
// path. resolveTarget times the lookup separately, and this function is then
// given a literal so the number it returns is the handshake and nothing else.
//
// The cost of that choice is that Happy Eyeballs is off: only the address the
// caller selected is tried. That is the trade this tool wants — diagnosis needs
// determinism more than it needs a connection to succeed.
func measure(ctx context.Context, dial netsys.DialFunc, ip net.IP, port string, timeout time.Duration) sample {
	dctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	start := time.Now()
	conn, err := dial(dctx, "tcp", net.JoinHostPort(ip.String(), port))
	elapsed := time.Since(start)

	if err != nil {
		return sample{ms: millis(elapsed), outcome: classifyDialError(err), err: err}
	}
	conn.Close()
	return sample{ms: millis(elapsed), outcome: outcomeOK}
}

// millis converts a duration to fractional milliseconds.
func millis(d time.Duration) float64 { return float64(d) / float64(time.Millisecond) }

// classifyDialError sorts a dial failure into the outcome categories.
//
// The timeout check comes first for the deadline sentinels, because a context
// that expired is reported by net.Dialer as a context error rather than as a
// net.Error, and checking the interface first would miss it.
func classifyDialError(err error) outcome {
	if err == nil {
		return outcomeOK
	}
	if errors.Is(err, context.DeadlineExceeded) ||
		errors.Is(err, context.Canceled) ||
		errors.Is(err, os.ErrDeadlineExceeded) {
		return outcomeTimeout
	}
	if errors.Is(err, syscall.ECONNREFUSED) {
		return outcomeRefused
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return outcomeTimeout
	}
	return outcomeOther
}

// sleep waits for d, returning early if the context is cancelled. The
// cancellation matters: an interval-bound run of a few hundred samples is
// otherwise deaf to Ctrl-C for the whole run.
func sleep(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// dialFunc returns the Env's dialer, falling back to a plain one so a zero Env
// still works.
func dialFunc(env *netsys.Env) netsys.DialFunc {
	if env != nil && env.Dial != nil {
		return env.Dial
	}
	d := &net.Dialer{Timeout: 5 * time.Second}
	return d.DialContext
}
