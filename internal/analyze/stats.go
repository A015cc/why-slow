// Package analyze holds the pure statistical machinery: no network, no clock,
// no OS calls. Everything here is deterministic given its inputs, which is what
// makes the cluster detector testable without a network stack.
package analyze

import (
	"math"
	"sort"
)

// Sort returns an ascending copy of vs.
func Sort(vs []float64) []float64 {
	out := make([]float64, len(vs))
	copy(out, vs)
	sort.Float64s(out)
	return out
}

// Percentile computes the p-th percentile (0..100) of sorted data using linear
// interpolation between closest ranks. This matches numpy's default method so
// numbers printed by this tool can be compared against analysis done elsewhere.
// The input must already be sorted; use Sort.
func Percentile(sorted []float64, p float64) float64 {
	n := len(sorted)
	if n == 0 {
		return math.NaN()
	}
	if n == 1 {
		return sorted[0]
	}
	if p <= 0 {
		return sorted[0]
	}
	if p >= 100 {
		return sorted[n-1]
	}
	rank := (p / 100) * float64(n-1)
	lo := int(math.Floor(rank))
	hi := int(math.Ceil(rank))
	if lo == hi {
		return sorted[lo]
	}
	return sorted[lo] + (rank-float64(lo))*(sorted[hi]-sorted[lo])
}

// Median returns the 50th percentile of sorted data.
func Median(sorted []float64) float64 { return Percentile(sorted, 50) }

// IQR returns the interquartile range of sorted data. Spread is reported with
// IQR rather than standard deviation throughout this tool: on the bimodal
// distributions we care about, stddev is dominated by the gap between modes and
// says nothing useful about either one.
func IQR(sorted []float64) float64 { return Percentile(sorted, 75) - Percentile(sorted, 25) }

// MAD returns the median absolute deviation of sorted data.
func MAD(sorted []float64) float64 {
	if len(sorted) == 0 {
		return math.NaN()
	}
	med := Median(sorted)
	dev := make([]float64, len(sorted))
	for i, v := range sorted {
		dev[i] = math.Abs(v - med)
	}
	return Median(Sort(dev))
}

// WilsonInterval returns the 95% Wilson score interval for k successes in n
// trials. This is used instead of the normal approximation because the loss
// rates we report are small and n is small, exactly the regime where the naive
// interval produces nonsense such as negative lower bounds.
func WilsonInterval(k, n int) (lo, hi float64) {
	if n <= 0 {
		return 0, 1
	}
	const z = 1.959963984540054 // 95%
	nf := float64(n)
	phat := float64(k) / nf
	z2 := z * z
	denom := 1 + z2/nf
	center := (phat + z2/(2*nf)) / denom
	margin := (z / denom) * math.Sqrt(phat*(1-phat)/nf+z2/(4*nf*nf))
	lo, hi = center-margin, center+margin
	if lo < 0 {
		lo = 0
	}
	if hi > 1 {
		hi = 1
	}
	return lo, hi
}

// Temporal describes how high-latency samples are arranged in time.
type Temporal string

const (
	// TemporalInterspersed means high samples are scattered, which is the
	// signature of memoryless packet loss.
	TemporalInterspersed Temporal = "interspersed"
	// TemporalClustered means high samples bunch together, which indicates
	// autocorrelated trouble: congestion or a struggling server, not random loss.
	TemporalClustered Temporal = "clustered"
	TemporalUnknown   Temporal = "unknown"
)

// RunsTest assesses whether the marked samples are interspersed or clustered in
// time. It returns the observed number of runs, the count of marked samples,
// and a z score against the null hypothesis of random ordering.
//
// Interpretation: a markedly negative z means fewer runs than chance, i.e. the
// marked samples clump together in time. That is evidence against memoryless
// loss, and it should downgrade any "packet loss" conclusion.
func RunsTest(marked []bool) (runs, nMarked int, z float64) {
	n := len(marked)
	for _, m := range marked {
		if m {
			nMarked++
		}
	}
	nOther := n - nMarked
	if nMarked == 0 || nOther == 0 || n < 2 {
		return 0, nMarked, 0
	}
	runs = 1
	for i := 1; i < n; i++ {
		if marked[i] != marked[i-1] {
			runs++
		}
	}
	nf, n1, n2 := float64(n), float64(nMarked), float64(nOther)
	expected := 2*n1*n2/nf + 1
	variance := (2 * n1 * n2 * (2*n1*n2 - nf)) / (nf * nf * (nf - 1))
	if variance <= 0 {
		return runs, nMarked, 0
	}
	return runs, nMarked, (float64(runs) - expected) / math.Sqrt(variance)
}

// ClassifyTemporal turns a runs-test z score into a verdict. The thresholds are
// deliberately generous: with n in the tens, the runs test is a weak instrument
// and we would rather say "unknown" than over-read it.
func ClassifyTemporal(z float64, nMarked, n int) Temporal {
	if nMarked < 4 || n < 12 {
		return TemporalUnknown
	}
	switch {
	case z <= -2.5:
		// Deliberately strict. At the sample sizes this tool uses, a -2.0
		// threshold trips on chance a good fraction of the time, and every false
		// "this is congestion, not loss" costs us a rung we would otherwise
		// report at full confidence.
		return TemporalClustered
	case z >= -0.5:
		return TemporalInterspersed
	default:
		return TemporalUnknown
	}
}
