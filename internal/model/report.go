package model

import "time"

// SchemaVersion is bumped whenever the JSON shape changes incompatibly. It is
// in every --json payload so scripts can pin against it.
const SchemaVersion = 1

// Verdict is the one-line answer to "why is it slow".
type Verdict struct {
	Level        Severity `json:"level"`
	PrimaryCause string   `json:"primary_cause,omitempty"`
	OneLiner     string   `json:"one_liner"`
}

// Report is the whole result of a run.
type Report struct {
	SchemaVersion int           `json:"schema_version"`
	Tool          string        `json:"tool"`
	Version       string        `json:"version"`
	StartedAt     time.Time     `json:"started_at"`
	DurationMS    float64       `json:"duration_ms"`
	Target        string        `json:"target,omitempty"`
	Observations  []Observation `json:"observations"`
	Findings      []Finding     `json:"findings"`
	Verdict       Verdict       `json:"verdict"`
	// ProbeErrors records probes that failed outright. A failing probe must not
	// abort the run: partial results are still worth reporting.
	ProbeErrors []ProbeError `json:"probe_errors,omitempty"`
}

// ProbeError records a probe that could not complete.
type ProbeError struct {
	Probe string `json:"probe"`
	Err   string `json:"error"`
}

// SortFindings orders findings worst-first, using priority as a tie-break.
// Renderers rely on this so they never have to reason about ordering.
func (r *Report) SortFindings() {
	f := r.Findings
	for i := 1; i < len(f); i++ {
		for j := i; j > 0; j-- {
			less := f[j].Severity > f[j-1].Severity ||
				(f[j].Severity == f[j-1].Severity && f[j].Priority > f[j-1].Priority)
			if !less {
				break
			}
			f[j], f[j-1] = f[j-1], f[j]
		}
	}
}
