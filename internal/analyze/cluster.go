package analyze

import (
	"math"

	"github.com/A015cc/why-slow/internal/model"
)

// TCP retransmission ladders.
//
// The initial RTO is quantized, not arbitrary. Linux and Windows 10/11 start at
// 1s (RFC 6298, which superseded RFC 2988's 3s), so the cumulative backoff
// ladder is 1s / 3s / 7s / 15s. Older Windows Server releases started at 3s,
// giving 3s / 9s / 21s.
//
// This quantization is the single strongest piece of evidence available to us.
// A genuinely slow server produces a shifted or smeared mode; it does not
// produce a mode pinned to baseline + exactly 1.000s. Multiple occupied rungs
// is close to conclusive for retransmission.
var (
	LadderModern = []float64{1000, 3000, 7000, 15000}
	LadderLegacy = []float64{3000, 9000, 21000}
)

// Options tunes detection. Use DefaultOptions and override sparingly.
type Options struct {
	// MinSamples below which no causal claim is made at all.
	MinSamples int
	// MinCluster is the fewest samples that can constitute a high mode. A single
	// outlier must never be promoted to a finding.
	MinCluster int
	// MinLowGroup is the fewest samples needed to establish a baseline.
	MinLowGroup int
	// MinGapMS is the smallest gap between the modes we will treat as a real
	// separation rather than measurement noise within one mode.
	MinGapMS float64
	// RungTolFrac / RungTolMinMS define how far from baseline+rung the cluster
	// centre may sit and still count as landing on that rung.
	RungTolFrac  float64
	RungTolMinMS float64
	// MaxClusterIQRFrac bounds the spread of the high mode. A wide high mode is
	// congestion, not a retransmit.
	MaxClusterIQRFrac float64
	// MaxBaselineIQRFrac bounds the spread of the low mode. If the baseline is
	// itself smeared there is no clean bimodal story to tell.
	MaxBaselineIQRFrac float64
	Ladders            [][]float64
}

// DefaultOptions returns the calibrated defaults.
func DefaultOptions() Options {
	return Options{
		MinSamples:         20,
		MinCluster:         3,
		MinLowGroup:        5,
		MinGapMS:           200,
		RungTolFrac:        0.25,
		RungTolMinMS:       200,
		MaxClusterIQRFrac:  0.25,
		MaxBaselineIQRFrac: 0.5,
		Ladders:            [][]float64{LadderModern, LadderLegacy},
	}
}

// Result is the outcome of cluster detection.
type Result struct {
	// Signal is true only when a ladder rung was matched with enough support.
	// When false, Reason explains why, and the caller should report the raw
	// numbers without any causal claim.
	Signal bool
	Reason string

	N          int
	BaselineMS float64
	Sorted     []float64

	// The matching rung and its cluster.
	RungMS     float64
	ClusterMS  float64
	ClusterN   int
	ClusterIQR float64
	LowN       int
	LowIQR     float64

	// Implied loss rate with a 95% Wilson interval.
	LossRate float64
	LossLo   float64
	LossHi   float64

	// Occupied lists every ladder rung that found support. Two or more is
	// near-conclusive for retransmission and raises confidence.
	Occupied []float64

	// CleanSplit records that the largest gap in the data sits at the boundary
	// of the primary cluster, leaving nothing stranded above it.
	CleanSplit bool

	RunsZ    float64
	Temporal Temporal

	Confidence model.Confidence

	// HighFlags marks which samples (in the original temporal order) belong to
	// the high mode. Feeds the sparkline and the runs test.
	HighFlags []bool
}

func rungTol(opts Options, rung float64) float64 {
	return math.Max(opts.RungTolMinMS, opts.RungTolFrac*rung)
}

// Detect looks for a retransmission ladder signature in TCP handshake timings.
//
// samples are connect() durations in milliseconds, in the order they were
// taken. Temporal order matters: it feeds the runs test that distinguishes
// memoryless loss from transient congestion.
//
// Callers must pass only completed measurements. A sample that hit the dial
// timeout is not a slow sample, it is a truncated one, and feeding it in here
// would fabricate exactly the cluster this function exists to find.
//
// Method: the largest gap in the samples locates the split between the low mode
// and everything above it. That split is then *validated against physics*: the
// high mode must sit at baseline plus a TCP retransmission timeout rung. Using
// the gap to find the boundary and the ladder to accept or reject it is what
// keeps this from being blind clustering, which at these sample sizes would
// happily fit a component to a single point.
func Detect(samples []float64, opts Options) Result {
	r := Result{N: len(samples), Sorted: Sort(samples)}
	if len(samples) == 0 {
		r.Reason = "no samples"
		return r
	}
	if len(samples) < opts.MinSamples {
		r.Reason = "too few samples to distinguish a cluster from noise"
		return r
	}

	sorted := r.Sorted

	// Locate the low mode using the largest gap. Measuring the baseline from
	// the low group rather than from the median of everything is essential:
	// once loss exceeds ~25% the 75th percentile lands inside the high cluster,
	// so a whole-sample IQR would report the baseline as wildly smeared.
	gapAt, gapSize := largestGap(sorted)
	if gapSize < opts.MinGapMS || gapAt < opts.MinLowGroup {
		r.Reason = "no separation between modes (timings are unimodal)"
		r.BaselineMS = Median(sorted)
		r.LowN = len(sorted)
		r.LowIQR = IQR(sorted)
		return r
	}

	lowGroup := sorted[:gapAt]
	baseline := Median(lowGroup)
	r.BaselineMS = baseline
	r.LowN = len(lowGroup)
	r.LowIQR = IQR(lowGroup)

	if r.LowIQR > opts.MaxBaselineIQRFrac*baseline {
		r.Reason = "the low mode is itself smeared, which points at congestion rather than a discrete retransmit event"
		return r
	}

	// Find the best-supported ladder rung. Scanning every rung rather than only
	// the largest gap's counterpart matters when several rungs are occupied,
	// e.g. a cluster at base+1s and another at base+3s.
	type match struct {
		rung    float64
		members []float64
	}
	var best *match
	// The ladders overlap on purpose (3000 appears in both), so dedupe: counting
	// one rung twice would fake the "two rungs occupied" evidence that earns the
	// highest confidence.
	seenRung := map[float64]bool{}
	for _, ladder := range opts.Ladders {
		for _, rung := range ladder {
			if seenRung[rung] {
				continue
			}
			t := rungTol(opts, rung)
			var members []float64
			for _, v := range sorted {
				if math.Abs(v-(baseline+rung)) <= t {
					members = append(members, v)
				}
			}
			if len(members) < opts.MinCluster {
				continue
			}
			if IQR(members) > opts.MaxClusterIQRFrac*rung {
				continue // smeared: not a quantized rung
			}
			seenRung[rung] = true
			r.Occupied = append(r.Occupied, rung)
			if best == nil || len(members) > len(best.members) {
				best = &match{rung: rung, members: members}
			}
		}
	}

	if best == nil {
		r.Reason = "the gap between modes does not align with any TCP retransmission ladder rung"
		return r
	}

	r.Signal = true
	r.RungMS = best.rung
	r.ClusterMS = Median(best.members)
	r.ClusterN = len(best.members)
	r.ClusterIQR = IQR(best.members)
	r.LossRate = float64(r.ClusterN) / float64(r.N)
	r.LossLo, r.LossHi = WilsonInterval(r.ClusterN, r.N)

	// Mark cluster membership in temporal order, then test the arrangement.
	lower := r.ClusterMS - rungTol(opts, best.rung)
	r.HighFlags = make([]bool, len(samples))
	for i, v := range samples {
		r.HighFlags[i] = v >= lower
	}
	_, _, r.RunsZ = RunsTest(r.HighFlags)
	r.Temporal = ClassifyTemporal(r.RunsZ, r.ClusterN, r.N)

	// The split is clean when every sample above the largest gap is accounted
	// for by some ladder rung. With one occupied rung that means nothing is
	// stranded between the modes. With two occupied rungs (base+1s and base+3s
	// together) the samples on the further rung are, by construction, outside
	// the primary cluster and must still count as explained: two quantized modes
	// a slow server cannot fake is exactly the case we want to score highest.
	r.CleanSplit = true
	for _, v := range sorted[gapAt:] {
		if !matchesAnyRung(v, baseline, opts) {
			r.CleanSplit = false
			break
		}
	}

	conf := model.ConfLow
	switch {
	case len(r.Occupied) >= 2 && r.CleanSplit:
		conf = model.ConfHigh
	case r.ClusterN >= 3 && r.N >= 30 && r.CleanSplit:
		conf = model.ConfMedium
	}
	// Temporal clumping is evidence against memoryless loss, so it weakens the
	// claim by one step. It weakens rather than vetoes: at high loss rates the
	// runs test has little power and clumps by chance, while the ladder
	// alignment is independent physical evidence that chance cannot supply.
	if r.Temporal == TemporalClustered && conf > model.ConfLow {
		conf--
	}
	r.Confidence = conf
	return r
}

// matchesAnyRung reports whether v sits on any rung of any known ladder,
// measured from the given baseline.
func matchesAnyRung(v, baseline float64, opts Options) bool {
	for _, ladder := range opts.Ladders {
		for _, rung := range ladder {
			if math.Abs(v-(baseline+rung)) <= rungTol(opts, rung) {
				return true
			}
		}
	}
	return false
}

// largestGap returns the index just above the widest gap between adjacent
// sorted samples, and the width of that gap.
func largestGap(sorted []float64) (idx int, size float64) {
	if len(sorted) < 2 {
		return 0, 0
	}
	idx, size = 1, sorted[1]-sorted[0]
	for i := 2; i < len(sorted); i++ {
		if d := sorted[i] - sorted[i-1]; d > size {
			size, idx = d, i
		}
	}
	return idx, size
}
