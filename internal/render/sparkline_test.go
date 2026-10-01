package render

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestSparklineEmpty(t *testing.T) {
	if got := Sparkline(nil, 10); got != "" {
		t.Fatalf("nil input: got %q, want empty", got)
	}
	if got := Sparkline([]float64{}, 10); got != "" {
		t.Fatalf("empty input: got %q, want empty", got)
	}
}

func TestSparklineSingle(t *testing.T) {
	got := Sparkline([]float64{42}, 10)
	if got != "▄" {
		t.Fatalf("single sample: got %q, want %q", got, "▄")
	}
	if n := utf8.RuneCountInString(got); n != 1 {
		t.Fatalf("single sample: %d runes, want 1", n)
	}
}

func TestSparklineAllIdentical(t *testing.T) {
	// Constant input must not divide by zero; it should draw a flat mid line.
	got := Sparkline([]float64{5, 5, 5, 5}, 0)
	want := strings.Repeat("▄", 4)
	if got != want {
		t.Fatalf("constant input: got %q, want %q", got, want)
	}
	if strings.Contains(strings.ToLower(got), "nan") {
		t.Fatalf("constant input produced NaN: %q", got)
	}

	// A single distinct value repeated many times is the same case at width.
	got = Sparkline(make([]float64, 100), 10)
	if got != strings.Repeat("▄", 10) {
		t.Fatalf("constant wide input: got %q", got)
	}
}

func TestSparklineDownsample(t *testing.T) {
	// Two tight groups must collapse to a low column and a high column.
	got := Sparkline([]float64{1, 1, 1, 1, 9, 9, 9, 9}, 2)
	if got != "▁█" {
		t.Fatalf("downsample: got %q, want %q", got, "▁█")
	}
	if n := utf8.RuneCountInString(got); n != 2 {
		t.Fatalf("downsample: %d runes, want 2", n)
	}

	// Never emit more columns than requested.
	got = Sparkline(make([]float64, 1000), 40)
	if n := utf8.RuneCountInString(got); n != 40 {
		t.Fatalf("downsample width: %d runes, want 40", n)
	}

	// Fewer samples than width means one column each.
	got = Sparkline([]float64{1, 2, 3}, 10)
	if n := utf8.RuneCountInString(got); n != 3 {
		t.Fatalf("small input: %d runes, want 3", n)
	}
}

func TestSparklineNaN(t *testing.T) {
	// NaN must not panic or produce a bogus level.
	got := Sparkline([]float64{1, nan(), 3}, 0)
	if n := utf8.RuneCountInString(got); n != 3 {
		t.Fatalf("nan input: %d runes, want 3 (%q)", n, got)
	}
	if strings.Contains(got, " ") || strings.Contains(got, "NaN") {
		t.Fatalf("nan input: unexpected content %q", got)
	}
}

func nan() float64 {
	var z float64
	return z / z
}
