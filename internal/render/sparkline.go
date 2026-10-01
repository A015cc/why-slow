package render

import (
	"math"
	"strings"
)

// sparkRunes are the eight Unicode block elements, lowest first. A strip of
// these is what lets a reader see a bimodal latency distribution at a glance:
// two runs of blocks at different heights are obvious in a way that a table of
// numbers never is.
var sparkRunes = []rune("▁▂▃▄▅▆▇█")

// sparkMid is the level used when every sample is identical. Drawing a flat
// constant at mid-height keeps it visibly a line rather than pinning it to the
// floor, and avoids the divide-by-zero of a min==max scale.
const sparkMid = 3

// Sparkline renders samples as a strip of block characters.
//
// width caps the number of runes emitted. When there are more samples than
// columns the input is downsampled by bucket mean, which preserves the shape of
// clustered data far better than dropping samples. A width <= 0 means "one
// column per sample".
//
// It is safe for empty input (returns ""), a single sample, and constant input.
// NaN samples are tolerated: they are drawn at the minimum level.
func Sparkline(samples []float64, width int) string {
	if len(samples) == 0 {
		return ""
	}
	if width <= 0 {
		width = len(samples)
	}
	if width < 1 {
		width = 1
	}

	vals := samples
	if len(samples) > width {
		vals = downsample(samples, width)
	}

	min, max := math.Inf(1), math.Inf(-1)
	for _, v := range vals {
		if math.IsNaN(v) {
			continue
		}
		if v < min {
			min = v
		}
		if v > max {
			max = v
		}
	}
	if math.IsInf(min, 1) {
		// Every value was NaN; draw a flat floor.
		return strings.Repeat(string(sparkRunes[0]), len(vals))
	}

	span := max - min
	var b strings.Builder
	b.Grow(len(vals))
	for _, v := range vals {
		if math.IsNaN(v) {
			v = min
		}
		idx := sparkMid
		if span > 0 {
			idx = int((v - min) / span * float64(len(sparkRunes)-1))
		}
		if idx < 0 {
			idx = 0
		}
		if idx > len(sparkRunes)-1 {
			idx = len(sparkRunes) - 1
		}
		b.WriteRune(sparkRunes[idx])
	}
	return b.String()
}

// downsample reduces samples to exactly width values, each the mean of the
// input values falling in its bucket. NaN values are skipped within a bucket.
func downsample(samples []float64, width int) []float64 {
	out := make([]float64, width)
	n := len(samples)
	for i := 0; i < width; i++ {
		lo := i * n / width
		hi := (i + 1) * n / width
		if hi <= lo {
			hi = lo + 1
		}
		var sum float64
		var cnt int
		for _, v := range samples[lo:hi] {
			if math.IsNaN(v) {
				continue
			}
			sum += v
			cnt++
		}
		if cnt == 0 {
			out[i] = math.NaN()
		} else {
			out[i] = sum / float64(cnt)
		}
	}
	return out
}
