package render

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/A015cc/why-slow/internal/model"
)

func TestJSONRoundTrip(t *testing.T) {
	r := bimodalReport()

	var buf bytes.Buffer
	if err := JSON(&buf, r); err != nil {
		t.Fatalf("JSON: %v", err)
	}

	var got model.Report
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if got.SchemaVersion != r.SchemaVersion {
		t.Errorf("schema_version = %d, want %d", got.SchemaVersion, r.SchemaVersion)
	}
	if got.Tool != r.Tool || got.Version != r.Version || got.Target != r.Target {
		t.Errorf("header round-trip mismatch: %+v", got)
	}
	if !got.StartedAt.Equal(r.StartedAt) {
		t.Errorf("started_at = %v, want %v", got.StartedAt, r.StartedAt)
	}
	if len(got.Observations) != len(r.Observations) {
		t.Fatalf("observations = %d, want %d", len(got.Observations), len(r.Observations))
	}
	if len(got.Observations[0].Series) != len(r.Observations[0].Series) {
		t.Errorf("series length = %d, want %d", len(got.Observations[0].Series), len(r.Observations[0].Series))
	}
	if got.Observations[0].Meta["ip"] != "203.0.113.10" {
		t.Errorf("meta round-trip lost: %+v", got.Observations[0].Meta)
	}
	if len(got.Findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(got.Findings))
	}
	if got.Findings[0].Severity != model.SevWarning {
		t.Errorf("severity = %v, want warning", got.Findings[0].Severity)
	}
	if got.Findings[0].Confidence != model.ConfMedium {
		t.Errorf("confidence = %v, want medium", got.Findings[0].Confidence)
	}
	if len(got.Findings[0].Evidence) != 1 || len(got.Findings[0].Evidence[0].Series) != 4 {
		t.Errorf("evidence round-trip mismatch: %+v", got.Findings[0].Evidence)
	}
	if got.Verdict.Level != model.SevWarning {
		t.Errorf("verdict level = %v, want warning", got.Verdict.Level)
	}
	if got.Verdict.OneLiner != r.Verdict.OneLiner {
		t.Errorf("one_liner = %q, want %q", got.Verdict.OneLiner, r.Verdict.OneLiner)
	}
}

func TestJSONSeverityConfidenceStrings(t *testing.T) {
	var buf bytes.Buffer
	if err := JSON(&buf, bimodalReport()); err != nil {
		t.Fatalf("JSON: %v", err)
	}
	s := buf.String()

	for _, want := range []string{
		`"severity": "warning"`,
		`"confidence": "medium"`,
		`"level": "warning"`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("JSON missing %s\n%s", want, s)
		}
	}

	// Two-space indent, struct-driven.
	if !strings.Contains(s, "\n  \"schema_version\": 1,") {
		t.Errorf("JSON not 2-space indented at top level:\n%s", s)
	}
	// Exactly one trailing newline.
	if !strings.HasSuffix(s, "}\n") || strings.HasSuffix(s, "}\n\n") {
		t.Errorf("JSON should end with a single newline, got %q", s[len(s)-4:])
	}
}

func TestJSONProbeErrors(t *testing.T) {
	r := bimodalReport()
	r.ProbeErrors = []model.ProbeError{{Probe: "dns", Err: "no such host"}}

	var buf bytes.Buffer
	if err := JSON(&buf, r); err != nil {
		t.Fatalf("JSON: %v", err)
	}
	if !strings.Contains(buf.String(), `"probe_errors"`) {
		t.Errorf("probe_errors omitted from JSON:\n%s", buf.String())
	}

	var got model.Report
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(got.ProbeErrors) != 1 || got.ProbeErrors[0].Probe != "dns" {
		t.Errorf("probe_errors round-trip mismatch: %+v", got.ProbeErrors)
	}
}
