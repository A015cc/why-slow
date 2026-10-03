//go:build integration && linux

package latency

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"testing"
	"time"

	"github.com/A015cc/why-slow/internal/analyze"
	"github.com/A015cc/why-slow/internal/model"
	"github.com/A015cc/why-slow/internal/probe/path"
)

// netemLossPercent is chosen to be unmistakable rather than realistic. A lossy
// transcontinental link might drop 2%; 20% guarantees several retransmits in 40
// samples, so a failure here means the detector is broken rather than unlucky.
const netemLossPercent = 20

// TestNetemRealLossProducesARetransmitCluster is the only test in this repository
// that validates the tool's central physical claim against genuinely dropped
// packets.
//
// Every other test of the ladder detector feeds it synthetic numbers, which
// proves the arithmetic and proves nothing about reality. This one makes the
// kernel actually lose 20% of the packets on the loopback interface, measures
// real handshakes through it, and asserts the detector finds the first
// retransmission rung at baseline + 1s. If the tool's headline claim is wrong —
// if a lost SYN does not produce a quantized +1s cluster, or the detector cannot
// see one — this is where it shows up.
//
// Two phases, and the first one matters as much as the second. Without the
// control, a passing run would only establish that loopback dials look bimodal,
// which is not the claim under test; the control is what makes the difference
// attributable to the induced loss.
//
// The test needs root and a `tc` binary, and it depends on a statistical
// outcome, so it is excluded from the default build and allowed to fail in CI.
// It is a diagnostic instrument, not a gate.
func TestNetemRealLossProducesARetransmitCluster(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	// Drain the accept queue. The kernel completes handshakes on its own, but a
	// listener that never accepts is not what a real target looks like.
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()

	target := ln.Addr().String()
	// Interval is zero here, unlike the CLI default. The 200ms gap exists to
	// avoid tripping a middlebox's or server's SYN flood protection, and there is
	// neither a middlebox nor a remote server on loopback — keeping it would only
	// make this test 8 seconds slower per phase.
	opts := Options{N: 40, Timeout: 5 * time.Second, Interval: 0}

	clean := measureSeries(t, target, opts)
	if res := analyze.Detect(clean, analyze.DefaultOptions()); res.Signal {
		t.Fatalf("the detector fired on clean loopback with no induced loss (rungs %v) — a "+
			"signal here would mean this test is measuring its own artefact, not the loss",
			res.Occupied)
	}
	t.Logf("control: n=%d, no loss induced, detector stayed silent as required", len(clean))

	if !applyNetem(t, netemLossPercent) {
		t.Skip("netem is unavailable (needs root and a tc binary); cannot induce real packet loss")
	}
	defer clearNetem(t)

	lossy := measureSeries(t, target, opts)
	res := analyze.Detect(lossy, analyze.DefaultOptions())

	t.Logf("induced %d%% loss on lo: n=%d baseline=%.3fms occupied rungs=%v confidence=%v temporal=%v",
		netemLossPercent, res.N, res.BaselineMS, res.Occupied, res.Confidence, res.Temporal)

	if !res.Signal {
		t.Fatalf("no retransmit cluster found despite %d%% real packet loss on lo (reason: %s)",
			netemLossPercent, res.Reason)
	}
	// The first rung specifically. Later rungs (3s, 7s) also show up at this loss
	// rate, and finding those would not prove the claim: the claim is that a
	// single lost handshake packet costs one initial RTO, which is 1s.
	if !containsRung(res.Occupied, 1000) {
		t.Fatalf("the detector did not occupy the first RTO rung (1000ms); it found %v from %d "+
			"samples, so the +1s signature did not survive contact with real loss", res.Occupied, res.N)
	}
}

// measureSeries runs the real latency probe against target and returns the
// completed handshake timings in the order they were taken.
func measureSeries(t *testing.T, target string, opts Options) []float64 {
	t.Helper()
	st := model.NewState()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	if err := New(nil, target, opts).Run(ctx, st); err != nil {
		t.Fatalf("latency probe: %v", err)
	}
	host, _ := path.NormalizeTarget(target)
	series := st.Series(probeName, KeyConnect, host)
	if len(series) == 0 {
		t.Fatalf("the probe recorded no completed handshakes against %s", target)
	}
	return series
}

// applyNetem installs a lossy qdisc on loopback and reports whether it worked.
func applyNetem(t *testing.T, lossPercent int) bool {
	t.Helper()
	err := tc("qdisc", "add", "dev", "lo", "root", "netem", "loss", fmt.Sprintf("%d%%", lossPercent))
	if err != nil {
		t.Logf("could not install netem: %v", err)
		return false
	}
	return true
}

// clearNetem removes the qdisc. Leaving it in place would make every later
// loopback connection on the machine lossy, which is a rude thing for a test to
// do to its host.
func clearNetem(t *testing.T) {
	t.Helper()
	if err := tc("qdisc", "del", "dev", "lo", "root"); err != nil {
		t.Logf("warning: the netem qdisc may still be installed on lo: %v", err)
	}
}

// tc runs the traffic-control binary, trying unprivileged first and then sudo.
//
// sudo is invoked with -n so that a machine requiring a password fails
// immediately instead of hanging on a prompt this test has no way to answer —
// a hung CI job is far more expensive to diagnose than a skipped test.
func tc(args ...string) error {
	if err := exec.Command("tc", args...).Run(); err == nil {
		return nil
	}
	return exec.Command("sudo", append([]string{"-n", "tc"}, args...)...).Run()
}

func containsRung(rungs []float64, want float64) bool {
	for _, r := range rungs {
		if r == want {
			return true
		}
	}
	return false
}
