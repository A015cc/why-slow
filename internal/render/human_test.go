package render

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/A015cc/why-slow/internal/model"
)

var update = flag.Bool("update", false, "regenerate golden files")

// checkGolden compares got against testdata/name, or rewrites it with -update.
func checkGolden(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if *update {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatalf("mkdir testdata: %v", err)
		}
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatalf("write golden: %v", err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden %s (run with -update to create): %v", path, err)
	}
	if got != string(want) {
		t.Errorf("rendered output does not match %s\n--- got ---\n%s\n--- want ---\n%s", path, got, want)
	}
}

func testTime() time.Time {
	return time.Date(2026, 10, 2, 15, 4, 5, 0, time.UTC)
}

// bimodalSeries is 36 low handshake samples (~151ms) with 4 samples at
// ~1151ms, i.e. baseline + 1.00s, spread through the run so the samples are
// interspersed in time rather than clumped.
func bimodalSeries() []float64 {
	low := []float64{
		148, 149, 150, 150, 151, 151, 151, 151, 152, 152, 152, 152,
		153, 153, 153, 154, 148, 149, 150, 150, 151, 151, 151, 151,
		152, 152, 152, 152, 153, 153, 153, 154, 150, 151, 152, 153,
	}
	high := []float64{1150, 1151, 1151, 1152}
	at := map[int]bool{7: true, 19: true, 28: true, 37: true}
	out := make([]float64, 0, 40)
	li, hi := 0, 0
	for i := 0; i < 40; i++ {
		if at[i] {
			out = append(out, high[hi])
			hi++
			continue
		}
		out = append(out, low[li])
		li++
	}
	return out
}

// bimodalReport is a hand-built retransmit diagnosis: no network involved.
func bimodalReport() *model.Report {
	at := testTime()
	series := bimodalSeries()

	obs := model.Observation{
		Probe:   "tcp",
		Subject: "vps.example.com:443",
		Key:     "latency",
		Unit:    "ms",
		Series:  series,
		At:      at,
		Meta:    map[string]string{"ip": "203.0.113.10"},
	}

	finding := model.New("tcp.retransmit", "tcp", model.SevWarning, model.ConfMedium,
		"Handshake stalls look like SYN retransmits",
		"consistent with a SYN retransmit (handshake loss), not server slowness").
		WithEvidence(
			model.EvSeries("cluster B", "4 samples, median 1.15s", "tcp.connect", []float64{1150, 1151, 1151, 1152}),
		).
		WithAdvice(
			"Re-run with more samples to tighten the loss estimate.",
			"Check for a middlebox or firewall dropping SYNs along the path.",
		).
		WithPriority(10)

	return &model.Report{
		SchemaVersion: model.SchemaVersion,
		Tool:          "why-slow",
		Version:       "0.1.0",
		StartedAt:     at,
		DurationMS:    1234,
		Target:        "vps.example.com:443",
		Observations:  []model.Observation{obs},
		Findings:      []model.Finding{finding},
		Verdict: model.Verdict{
			Level:        model.SevWarning,
			PrimaryCause: "handshake packet loss",
			OneLiner:     "About 10% of handshake attempts needed a retransmit, adding roughly 1s to those connections.",
		},
	}
}

func renderHuman(t *testing.T, r *model.Report, opts Options) string {
	t.Helper()
	var buf bytes.Buffer
	if err := Human(&buf, r, opts); err != nil {
		t.Fatalf("Human: %v", err)
	}
	return buf.String()
}

func TestHumanBimodalGolden(t *testing.T) {
	got := renderHuman(t, bimodalReport(), Options{Color: false, Width: 80})
	checkGolden(t, "bimodal.golden", got)

	if strings.Contains(got, "\x1b[") {
		t.Errorf("colour leaked with Options.Color=false:\n%s", got)
	}
	// The sparkline and both clusters must be present: that is the product.
	for _, want := range []string{"LATENCY", "samples", "cluster A", "cluster B", "VERDICT", "FINDINGS"} {
		if !strings.Contains(got, want) {
			t.Errorf("output missing %q:\n%s", want, got)
		}
	}
}

func TestHumanColorGolden(t *testing.T) {
	got := renderHuman(t, bimodalReport(), Options{Color: true, Width: 80})
	checkGolden(t, "bimodal_color.golden", got)
	if !strings.Contains(got, "\x1b[") {
		t.Errorf("Options.Color=true produced no ANSI codes:\n%s", got)
	}
}

func TestHumanProbeErrorsGolden(t *testing.T) {
	r := bimodalReport()
	r.ProbeErrors = []model.ProbeError{
		{Probe: "dns", Err: "lookup nope.invalid: no such host"},
		{Probe: "http", Err: "context deadline exceeded"},
	}
	got := renderHuman(t, r, Options{Color: false, Width: 80})
	checkGolden(t, "probe_errors.golden", got)

	if !strings.Contains(got, "PROBE ERRORS") {
		t.Errorf("probe errors not surfaced:\n%s", got)
	}
	if !strings.Contains(got, "context deadline exceeded") {
		t.Errorf("probe error text missing:\n%s", got)
	}
}

func TestHumanZeroFindingsGolden(t *testing.T) {
	r := bimodalReport()
	r.Findings = nil
	r.Verdict = model.Verdict{
		Level:    model.SevInfo,
		OneLiner: "No significant problems detected; latency is well behaved.",
	}
	got := renderHuman(t, r, Options{Color: false, Width: 80})
	checkGolden(t, "zero_findings.golden", got)

	if strings.Contains(got, "FINDINGS") {
		t.Errorf("findings section rendered with zero findings:\n%s", got)
	}
	if !strings.Contains(got, "VERDICT") {
		t.Errorf("verdict missing:\n%s", got)
	}
}

func TestHumanWidthZeroDefaults(t *testing.T) {
	// Width 0 must not panic or collapse the sparkline.
	var buf bytes.Buffer
	if err := Human(&buf, bimodalReport(), Options{Color: false}); err != nil {
		t.Fatalf("Human: %v", err)
	}
	if buf.Len() == 0 {
		t.Fatal("empty output")
	}
}
