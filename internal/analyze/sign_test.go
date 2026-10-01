package analyze

import (
	"math"
	"testing"
)

func TestBinomTwoSidedPKnownValues(t *testing.T) {
	// Values below are exact: the binomial pmf at p=1/2 is k/2^n.
	cases := []struct {
		k, n int
		want float64
	}{
		{0, 10, 2.0 / 1024.0},  // both tails are just the single point mass
		{10, 10, 2.0 / 1024.0}, // symmetric with k=0
		{5, 10, 1.0},           // the central case, capped rather than >1
		{0, 1, 1.0},
		{1, 1, 1.0},
		{0, 0, 1.0},
		{3, 4, 2.0 * (1 + 4) / 16.0},
	}
	for _, c := range cases {
		got := BinomTwoSidedP(c.k, c.n)
		if math.Abs(got-c.want) > 1e-12 {
			t.Errorf("BinomTwoSidedP(%d,%d) = %v, want %v", c.k, c.n, got, c.want)
		}
	}
}

// A p-value must stay inside [0,1] even for the extreme tails, because it is
// multiplied by two on the way out and a naive implementation drifts above 1.
func TestBinomTwoSidedPStaysInRange(t *testing.T) {
	for n := 1; n <= 200; n++ {
		for k := 0; k <= n; k++ {
			p := BinomTwoSidedP(k, n)
			if p < 0 || p > 1 || math.IsNaN(p) {
				t.Fatalf("BinomTwoSidedP(%d,%d) = %v, out of range", k, n, p)
			}
		}
	}
}

func TestSignTestAllOneDirection(t *testing.T) {
	r := SignTest([]float64{5, 7, 9, 11, 13})
	if r.N != 5 || r.Positive != 5 || r.Ties != 0 {
		t.Fatalf("got N=%d Positive=%d Ties=%d, want 5/5/0", r.N, r.Positive, r.Ties)
	}
	if want := 2.0 / 32.0; math.Abs(r.PValue-want) > 1e-12 {
		t.Errorf("PValue = %v, want %v", r.PValue, want)
	}
	if r.MedianDelta != 9 {
		t.Errorf("MedianDelta = %v, want 9", r.MedianDelta)
	}
}

// Ties carry no direction, so they are dropped from n rather than split
// arbitrarily in one direction. Counting them as successes would let a run of
// identical measurements manufacture significance out of a real difference of
// zero.
func TestSignTestExcludesTies(t *testing.T) {
	r := SignTest([]float64{0, 0, 5, 5, 5})
	if r.Ties != 2 {
		t.Errorf("Ties = %d, want 2", r.Ties)
	}
	if r.N != 3 {
		t.Errorf("N = %d, want 3 (ties excluded)", r.N)
	}
	if r.Positive != 3 {
		t.Errorf("Positive = %d, want 3", r.Positive)
	}
	if want := 0.25; math.Abs(r.PValue-want) > 1e-12 { // 2 * (1/8)
		t.Errorf("PValue = %v, want %v", r.PValue, want)
	}
}

func TestSignTestEmptyAndSymmetric(t *testing.T) {
	if r := SignTest(nil); r.PValue != 1 || r.N != 0 {
		t.Errorf("empty input: got N=%d P=%v, want 0/1", r.N, r.PValue)
	}
	// Perfectly balanced signs are the maximal-p case and must be exactly 1,
	// which is the value the "no evidence of a real difference" rule keys on.
	r := SignTest([]float64{1, -1, 2, -2})
	if r.N != 4 || r.Positive != 2 {
		t.Fatalf("got N=%d Positive=%d, want 4/2", r.N, r.Positive)
	}
	if r.PValue != 1 {
		t.Errorf("PValue = %v, want exactly 1", r.PValue)
	}
}

// The median delta keeps its sign: the direction of the effect has to survive
// into the report, because "B is slower" and "A is slower" lead to different
// advice.
func TestSignTestMedianKeepsSign(t *testing.T) {
	r := SignTest([]float64{-10, -20, -30})
	if r.MedianDelta != -20 {
		t.Errorf("MedianDelta = %v, want -20", r.MedianDelta)
	}
}
