package analyze

import "math"

// SignResult is the outcome of a paired sign test over within-pair differences.
type SignResult struct {
	// N is the number of pairs the test actually used, ties excluded.
	N int
	// Positive counts pairs where the second measurement was the larger one.
	Positive int
	// Ties counts pairs that differed by exactly zero; they carry no sign and are
	// excluded from N rather than being split arbitrarily.
	Ties int
	// MedianDelta is the median of the signed differences, kept signed so the
	// direction of the effect survives.
	MedianDelta float64
	// PValue is the two-sided exact binomial p-value under the null hypothesis
	// that each pair's sign is a fair coin.
	PValue float64
}

// SignTest runs the paired sign test on a set of within-pair differences.
//
// This is the right test for interleaved A/B comparison of handshake timings,
// for two reasons. First, the data are not normal — whenever retransmits are in
// play the distribution is bimodal, so a t-test would be reporting on a
// quantity that does not exist. Second, the sign test throws away magnitude
// entirely and keeps only direction, which makes it immune to the failure mode
// that motivates the whole interleaved design: a link that drifts during the run
// shifts both members of a pair together, so drift cancels out of the sign
// rather than accumulating into a fake effect.
//
// A large p-value is the useful result. It is the tool's way of saying "the
// three-fold difference a sequential test reported was drift, not a property of
// the two targets".
func SignTest(deltas []float64) SignResult {
	r := SignResult{Ties: 0}
	if len(deltas) == 0 {
		r.PValue = 1
		return r
	}
	pos := 0
	for _, d := range deltas {
		switch {
		case d > 0:
			pos++
		case d == 0:
			r.Ties++
		}
	}
	r.Positive = pos
	r.N = len(deltas) - r.Ties
	r.MedianDelta = Median(Sort(deltas))
	r.PValue = BinomTwoSidedP(pos, r.N)
	return r
}

// BinomTwoSidedP returns the exact two-sided binomial p-value for k successes in
// n trials at p=0.5.
//
// Terms are evaluated in log space via Lgamma rather than by multiplying out
// binomial coefficients. The direct product overflows float64 somewhere around
// n=1000, and although this tool's pair counts are an order of magnitude
// smaller, a statistics helper that silently returns +Inf at a plausible input
// size is a trap worth not leaving behind.
func BinomTwoSidedP(k, n int) float64 {
	if n <= 0 {
		return 1
	}
	if k < 0 {
		k = 0
	}
	if k > n {
		k = n
	}
	// Sum the smaller tail: it converges faster and costs less cancellation.
	lower := k
	if n-k < lower {
		lower = n - k
	}
	ln2n := float64(n) * math.Ln2
	lgn, _ := math.Lgamma(float64(n) + 1)
	sum := 0.0
	for i := 0; i <= lower; i++ {
		li, _ := math.Lgamma(float64(i) + 1)
		lm, _ := math.Lgamma(float64(n-i) + 1)
		sum += math.Exp(lgn - li - lm - ln2n)
	}
	p := 2 * sum
	if p > 1 {
		p = 1
	}
	return p
}
