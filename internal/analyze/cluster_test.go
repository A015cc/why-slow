package analyze

import (
	"math"
	"math/rand"
	"testing"

	"github.com/A015cc/why-slow/internal/model"
)

// synth produces a bimodal sample set: baseline with probability 1-loss, and
// baseline+rto with probability loss. Jitter is proportional to the mode centre
// so that a 20ms baseline and a 300ms baseline are equally "tight".
func synth(n int, loss, base, jitterFrac, rto float64, seed int64) []float64 {
	rng := rand.New(rand.NewSource(seed))
	out := make([]float64, n)
	for i := range out {
		centre := base
		if rng.Float64() < loss {
			centre = base + rto
		}
		out[i] = centre + rng.NormFloat64()*jitterFrac*centre
	}
	return out
}

// synthUnimodalLognormal produces a right-skewed single mode, which is what
// real RTT distributions look like. The detector must not split these.
func synthUnimodalLognormal(n int, median, sigma float64, seed int64) []float64 {
	rng := rand.New(rand.NewSource(seed))
	out := make([]float64, n)
	for i := range out {
		out[i] = median * math.Exp(rng.NormFloat64()*sigma)
	}
	return out
}

func TestDetectFindsLadderCluster(t *testing.T) {
	for _, loss := range []float64{0.10, 0.20, 0.30, 0.40} {
		for _, base := range []float64{20, 150, 300} {
			for _, rto := range []float64{1000, 3000} {
				seed := int64(loss*1000) + int64(base) + int64(rto)
				// n=100 rather than 60: at 10% loss a 60-sample draw yields fewer
				// than MinCluster high samples often enough (~4%) to make the test
				// flaky for a reason that has nothing to do with the detector.
				// Declining to conclude from 2 high samples is correct behaviour.
				s := synth(100, loss, base, 0.05, rto, seed)
				r := Detect(s, DefaultOptions())

				if !r.Signal {
					t.Errorf("loss=%.2f base=%.0f rto=%.0f: no signal (reason: %s)", loss, base, rto, r.Reason)
					continue
				}
				if got, want := r.RungMS, rto; got != want {
					t.Errorf("loss=%.2f base=%.0f rto=%.0f: rung = %.0f, want %.0f", loss, base, rto, got, want)
				}
				if math.Abs(r.ClusterMS-(base+rto)) > 0.2*rto {
					t.Errorf("loss=%.2f base=%.0f rto=%.0f: cluster centre %.0f, want near %.0f", loss, base, rto, r.ClusterMS, base+rto)
				}
				if math.Abs(r.BaselineMS-base) > 0.15*base {
					t.Errorf("loss=%.2f base=%.0f rto=%.0f: baseline %.0f, want near %.0f", loss, base, rto, r.BaselineMS, base)
				}
				// Membership must be exact: every sample the generator placed on
				// the rung belongs to the cluster, and nothing else does.
				var trueHigh int
				for _, v := range s {
					if v > base+0.5*rto {
						trueHigh++
					}
				}
				if r.ClusterN != trueHigh {
					t.Errorf("loss=%.2f base=%.0f rto=%.0f: cluster membership %d, want %d", loss, base, rto, r.ClusterN, trueHigh)
				}
				if r.LossRate < r.LossLo || r.LossRate > r.LossHi {
					t.Errorf("loss=%.2f base=%.0f rto=%.0f: rate %.3f outside its own CI [%.3f,%.3f]", loss, base, rto, r.LossRate, r.LossLo, r.LossHi)
				}
				if r.LossLo > loss || r.LossHi < loss {
					t.Logf("note: true loss %.2f outside reported CI [%.3f,%.3f] at n=%d", loss, r.LossLo, r.LossHi, r.N)
				}
			}
		}
	}
}

// The negative cases matter more than the positive ones: a diagnostic tool that
// cries wolf is worse than no tool at all.
func TestDetectRejectsUnimodal(t *testing.T) {
	for _, sigma := range []float64{0.05, 0.15, 0.30} {
		for _, seed := range []int64{1, 2, 3} {
			s := synthUnimodalLognormal(60, 150, sigma, seed)
			r := Detect(s, DefaultOptions())
			if r.Signal {
				t.Errorf("sigma=%.2f seed=%d: false positive, claimed rung %.0f with %d members", sigma, seed, r.RungMS, r.ClusterN)
			}
		}
	}
}

func TestDetectRejectsSingleOutlier(t *testing.T) {
	// A tight unimodal baseline with one wild sample must not become a finding:
	// a single point can never constitute a mode.
	s := synth(40, 0, 150, 0.03, 0, 7)
	s[17] = 150 + 1000
	r := Detect(s, DefaultOptions())
	if r.Signal {
		t.Errorf("single outlier produced a finding: rung=%.0f n=%d", r.RungMS, r.ClusterN)
	}
}

func TestDetectRequiresMinimumCluster(t *testing.T) {
	// Two samples on a rung is below MinCluster (3) and must be reported as a
	// bare observation, not a cause.
	s := synth(40, 0, 150, 0.03, 0, 11)
	s[5], s[23] = 1150, 1155
	r := Detect(s, DefaultOptions())
	if r.Signal {
		t.Errorf("2-sample cluster accepted: rung=%.0f n=%d", r.RungMS, r.ClusterN)
	}
}

func TestDetectRejectsSubThresholdSeparation(t *testing.T) {
	// Two modes only 200ms apart is below the physical ladder spacing and must
	// not be reported as a retransmit.
	s := synth(60, 0.3, 150, 0.02, 200, 13)
	r := Detect(s, DefaultOptions())
	if r.Signal {
		t.Errorf("200ms separation accepted as a ladder rung: rung=%.0f", r.RungMS)
	}
}

func TestDetectRejectsTooFewSamples(t *testing.T) {
	s := synth(12, 0.3, 150, 0.03, 1000, 17)
	r := Detect(s, DefaultOptions())
	if r.Signal {
		t.Error("reached a conclusion from 12 samples")
	}
	if r.Reason == "" {
		t.Error("expected a reason when declining to conclude")
	}
}

func TestDetectMultiRungRaisesConfidence(t *testing.T) {
	// Samples on two rungs (base+1s and base+3s) is close to conclusive for
	// retransmission, because a slow server cannot fake two quantized modes.
	rng := rand.New(rand.NewSource(23))
	var s []float64
	for i := 0; i < 60; i++ {
		switch {
		case rng.Float64() < 0.15:
			s = append(s, 150+3000+rng.NormFloat64()*5)
		case rng.Float64() < 0.25:
			s = append(s, 150+1000+rng.NormFloat64()*5)
		default:
			s = append(s, 150+rng.NormFloat64()*5)
		}
	}
	r := Detect(s, DefaultOptions())
	if !r.Signal {
		t.Fatalf("no signal on a two-rung set: %s", r.Reason)
	}
	if len(r.Occupied) < 2 {
		t.Errorf("expected 2 occupied rungs, got %v", r.Occupied)
	}
	if r.Confidence != model.ConfHigh {
		t.Errorf("two occupied rungs should reach high confidence, got %v", r.Confidence)
	}
}

// A single occupied rung must never reach high confidence. Regression test for a
// bug where 3000 appeared in both ladders and was counted twice, so one rung
// looked like two and earned high confidence it had not earned.
func TestDetectSingleLegacyRungIsNotHighConfidence(t *testing.T) {
	s := synth(60, 0.25, 150, 0.05, 3000, 3190)
	r := Detect(s, DefaultOptions())
	if !r.Signal {
		t.Fatalf("no signal: %s", r.Reason)
	}
	if len(r.Occupied) != 1 {
		t.Errorf("expected exactly 1 occupied rung, got %v", r.Occupied)
	}
	if r.Confidence == model.ConfHigh {
		t.Error("a single rung must not reach high confidence")
	}
	if r.Confidence != model.ConfMedium {
		t.Errorf("expected medium confidence, got %v", r.Confidence)
	}
}

func TestDetectEmptyAndTiny(t *testing.T) {
	for _, s := range [][]float64{nil, {}, {150}, {150, 160}} {
		r := Detect(s, DefaultOptions()) // must not panic
		if r.Signal {
			t.Errorf("signal from %v", s)
		}
	}
}

func TestWilsonIntervalSanity(t *testing.T) {
	lo, hi := WilsonInterval(0, 20)
	if lo != 0 {
		t.Errorf("lower bound for zero successes = %v, want 0", lo)
	}
	if hi <= 0 || hi > 1 {
		t.Errorf("upper bound = %v, want in (0,1]", hi)
	}
	lo, hi = WilsonInterval(20, 20)
	if hi != 1 {
		t.Errorf("upper bound for all successes = %v, want 1", hi)
	}
	if lo >= 1 {
		t.Errorf("lower bound = %v, want < 1", lo)
	}
	lo, hi = WilsonInterval(4, 40)
	if lo < 0 || hi > 1 || lo >= hi {
		t.Errorf("interval [%v,%v] malformed", lo, hi)
	}
}

func TestPercentileMatchesKnownValues(t *testing.T) {
	s := []float64{1, 2, 3, 4}
	if got := Percentile(s, 0); got != 1 {
		t.Errorf("p0 = %v", got)
	}
	if got := Percentile(s, 100); got != 4 {
		t.Errorf("p100 = %v", got)
	}
	if got := Percentile(s, 50); got != 2.5 {
		t.Errorf("p50 = %v, want 2.5", got)
	}
	if got := Percentile(s, 25); got != 1.75 {
		t.Errorf("p25 = %v, want 1.75", got)
	}
}

func TestRunsTestDetectsClustering(t *testing.T) {
	// All marks bunched at the front: far fewer runs than chance.
	clustered := append([]bool{true, true, true, true, true, true}, make([]bool, 14)...)
	_, _, z := RunsTest(clustered)
	if z > -1.5 {
		t.Errorf("clustered marks gave z=%.2f, expected clearly negative", z)
	}
	// Perfectly alternating: far more runs than chance.
	var spread []bool
	for i := 0; i < 20; i++ {
		spread = append(spread, i%2 == 0)
	}
	if _, _, z := RunsTest(spread); z < 1.5 {
		t.Errorf("alternating marks gave z=%.2f, expected clearly positive", z)
	}
}
