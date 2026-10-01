// Package latency answers "how long does a connection to this target take, and
// is the shape of those numbers telling us something".
//
// Two choices separate this from an ordinary TCP ping, and both are load
// bearing.
//
// DNS is timed separately and never folded into the handshake. A slow resolver
// and a lossy path are different problems with different fixes, and a single
// "connect time" blends them into one figure nobody can act on. So the lookup is
// recorded as dns.lookup_ms, and the handshake is then measured against an IP
// literal.
//
// The default dial timeout is 5s rather than the 1-2s a ping tool would pick.
// That is not a stylistic preference. The signature this tool exists to find is
// a cluster of samples sitting at baseline + one TCP initial RTO, which is 1s on
// Linux and Windows 10/11. A 1-2s timeout truncates precisely those samples, and
// the tool's one distinctive capability degrades into an ordinary timeout
// report. The timeout is therefore part of the method, not a knob to be tuned
// down casually.
package latency

import (
	"context"
	"errors"
	"net"
	"strconv"
	"time"

	"github.com/A015cc/why-slow/internal/model"
	"github.com/A015cc/why-slow/internal/netsys"
	"github.com/A015cc/why-slow/internal/probe"
	"github.com/A015cc/why-slow/internal/probe/path"
)

const probeName = "latency"

// Compile-time proof that Probe satisfies the probe contract.
var _ probe.Probe = (*Probe)(nil)

// Observation keys. These are the contract with the verdict engine, which reads
// observations back by name; naming them here is what stops a rename in this
// package from silently desynchronising it from the rules on the other side.
const (
	// KeyConnect is the series of completed TCP handshake durations in
	// milliseconds, in measurement order. Temporal order is preserved on purpose:
	// the cluster detector's runs test separates memoryless loss (interspersed)
	// from congestion (clumped), and that distinction changes the conclusion.
	KeyConnect = "tcp.connect"
	// KeyDNSLookup is the resolver round trip in milliseconds. Absent for an IP
	// literal, where there was no lookup to time.
	KeyDNSLookup = "dns.lookup_ms"
	// KeyAttempts is how many dials were attempted.
	KeyAttempts = "latency.attempts_n"
	// KeyTruncated counts dials that reached the deadline. A truncated sample is
	// not a slow sample, and must never be fed to the cluster detector: dropping
	// a batch of them at the timeout value would manufacture a high mode, which
	// is precisely the artefact the detector is meant to find rather than invent.
	KeyTruncated = "latency.truncated_n"
	// KeyRefused counts dials answered with a RST, meaning the host is reachable
	// and the port is closed. A different diagnosis from silence.
	KeyRefused = "latency.refused_n"
	// KeyDialErrors counts dials that failed for any other reason.
	KeyDialErrors = "latency.dial_errors_n"
	// KeyDialError carries the most recent failure verbatim.
	KeyDialError = "latency.dial_error"
)

// Observations for the interleaved A/B comparison. All of these share a single
// subject, "<A> vs <B>", so the whole comparison reads back with one lookup.
const (
	KeyABSummary  = "ab.summary"
	KeyABLabelA   = "ab.label_a"
	KeyABLabelB   = "ab.label_b"
	KeyABPairs    = "ab.pairs_n"
	KeyABSkipped  = "ab.skipped_n"
	KeyABDelta    = "ab.delta_ms"
	KeyABMedian   = "ab.median_delta_ms"
	KeyABPValue   = "ab.p_value"
	KeyABPositive = "ab.second_slower_n"
	KeyABTies     = "ab.ties_n"
)

// Options configures a latency run.
type Options struct {
	// N is the number of handshake attempts per target. The default of 40 is set
	// by what the detector can support: below about 20 samples it makes no causal
	// claim at all, and a "p95" computed from 20 samples is literally the largest
	// sample, which is not a statistic.
	N int
	// Timeout bounds each individual dial. See the package comment for why the
	// default is 5s.
	Timeout time.Duration
	// Interval is the gap between consecutive attempts. Roughly 200ms by default:
	// attempts fired back to back can trip a middlebox's or server's SYN flood
	// protection, which would manufacture the very bimodality this tool is
	// looking for. Zero is a legitimate value and means "no gap", so only a
	// negative duration falls back to the default.
	Interval time.Duration
	// Family restricts the address family: "4", "6", or "auto".
	Family string
	// AllIPs measures every resolved address rather than just the preferred one,
	// which is how a multi-homed target's per-address behaviour becomes visible.
	AllIPs bool
	// Compare names a second target to measure against in an interleaved A/B run.
	Compare string
	// Pairs is the number of A/B pairs to measure.
	Pairs int
	// Coin decides which side of a pair is measured first. It is injected rather
	// than called directly so the interleaving can be driven deterministically in
	// tests; nil means a real coin.
	Coin func() bool
}

// DefaultOptions returns the calibrated defaults.
func DefaultOptions() Options {
	return Options{
		N:        40,
		Timeout:  5 * time.Second,
		Interval: 200 * time.Millisecond,
		Family:   "auto",
		Pairs:    20,
	}
}

func (o Options) withDefaults() Options {
	d := DefaultOptions()
	if o.N <= 0 {
		o.N = d.N
	}
	if o.Timeout <= 0 {
		o.Timeout = d.Timeout
	}
	if o.Interval < 0 {
		o.Interval = d.Interval
	}
	if o.Family == "" {
		o.Family = d.Family
	}
	if o.Pairs <= 0 {
		o.Pairs = d.Pairs
	}
	return o
}

// Probe measures TCP handshake timings toward one target.
type Probe struct {
	env    *netsys.Env
	target string
	opts   Options
}

// New builds a latency probe for target, which may be a hostname, an IP literal,
// or either with a ":port" suffix.
func New(env *netsys.Env, target string, opts Options) *Probe {
	return &Probe{env: env, target: target, opts: opts}
}

// Name implements probe.Probe.
func (p *Probe) Name() string { return probeName }

// Run records the latency observations.
//
// It returns an error only when the probe could not do its job at all — an
// unresolvable name, or a family the name has no address in. A target that
// refused every connection, or that swallowed every attempt, is a *result*: the
// counts are the diagnosis, and they are recorded rather than reported as a
// failure.
func (p *Probe) Run(ctx context.Context, st *model.State) error {
	env := p.env
	if env == nil {
		env = netsys.DefaultEnv()
	}
	opts := p.opts.withDefaults()

	host, port := path.NormalizeTarget(p.target)
	if host == "" {
		return errors.New("latency: empty target")
	}

	res, err := resolveTarget(ctx, env, host, opts.Family)
	if err != nil {
		st.Add(model.Text(probeName, host, KeyDialError, err.Error(),
			map[string]string{"target": p.target, "phase": "resolve"}))
		return err
	}
	if res.didLookup {
		st.Add(model.Num(probeName, host, KeyDNSLookup, "ms", res.ms,
			map[string]string{"target": p.target, "addresses": formatIPs(res.ips)}))
	}

	targets := pickTargets(res.ips, opts)
	if len(targets) == 0 {
		return errors.New("latency: no address to measure for " + p.target)
	}
	for _, ip := range targets {
		p.measureOne(ctx, st, env, ip, port, opts)
		if err := ctx.Err(); err != nil {
			return err
		}
	}

	if opts.Compare != "" {
		// A comparison that could not run does not invalidate the single-target
		// numbers already recorded, so it is reported as an observation rather
		// than propagated as a probe failure.
		if err := p.compare(ctx, st, env, targets[0], port, opts); err != nil {
			st.Add(model.Text(probeName, p.target+" vs "+opts.Compare, KeyABSummary, err.Error(), nil))
		}
	}
	return nil
}

// measureOne takes opts.N samples against one address and records them.
func (p *Probe) measureOne(ctx context.Context, st *model.State, env *netsys.Env, ip net.IP, port string, opts Options) {
	dial := dialFunc(env)
	subject := ip.String()
	md := map[string]string{
		"target":      p.target,
		"resolved_ip": subject,
		"timeout_ms":  strconv.FormatInt(opts.Timeout.Milliseconds(), 10),
		"interval_ms": strconv.FormatInt(opts.Interval.Milliseconds(), 10),
		"family":      opts.Family,
	}

	series := make([]float64, 0, opts.N)
	var truncated, refused, other int
	var lastErr error

	for i := 0; i < opts.N; i++ {
		if i > 0 {
			if err := sleep(ctx, opts.Interval); err != nil {
				// Cancelled mid-run. Keep what was measured: a partial series is
				// still evidence, and discarding it would make Ctrl-C lose the
				// run's only output.
				break
			}
		}
		s := measure(ctx, dial, ip, port, opts.Timeout)
		switch s.outcome {
		case outcomeOK:
			series = append(series, s.ms)
		case outcomeTimeout:
			truncated++
			lastErr = s.err
		case outcomeRefused:
			refused++
			lastErr = s.err
		default:
			other++
			lastErr = s.err
		}
	}

	obs := make([]model.Observation, 0, 6)
	if len(series) > 0 {
		obs = append(obs, model.Series(probeName, subject, KeyConnect, "ms", series, md))
	}
	obs = append(obs,
		model.Num(probeName, subject, KeyAttempts, "count", float64(opts.N), md),
		model.Num(probeName, subject, KeyTruncated, "count", float64(truncated), md),
		model.Num(probeName, subject, KeyRefused, "count", float64(refused), md),
		model.Num(probeName, subject, KeyDialErrors, "count", float64(other), md),
	)
	if lastErr != nil {
		obs = append(obs, model.Text(probeName, subject, KeyDialError, lastErr.Error(), md))
	}
	st.Add(obs...)
}
