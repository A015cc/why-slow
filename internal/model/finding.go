package model

import (
	"encoding/json"
	"fmt"
)

// Severity says how much this finding hurts the user.
type Severity int

const (
	SevInfo Severity = iota
	SevNotice
	SevWarning
	SevCritical
)

var sevNames = map[Severity]string{
	SevInfo:     "info",
	SevNotice:   "notice",
	SevWarning:  "warning",
	SevCritical: "critical",
}

func (s Severity) String() string {
	if n, ok := sevNames[s]; ok {
		return n
	}
	return "unknown"
}

func (s Severity) MarshalJSON() ([]byte, error) { return json.Marshal(s.String()) }

func (s *Severity) UnmarshalJSON(b []byte) error {
	var n string
	if err := json.Unmarshal(b, &n); err != nil {
		return err
	}
	for k, v := range sevNames {
		if v == n {
			*s = k
			return nil
		}
	}
	return fmt.Errorf("unknown severity %q", n)
}

// Confidence says how sure we are. It is deliberately orthogonal to Severity:
// a finding can be severe but uncertain ("this looks like handshake loss, but a
// middlebox could produce the same shape"), and the report must say both.
//
// This axis is the mechanical guarantee that the tool does not overclaim, and
// overclaiming is exactly what would make it useless as a diagnostic.
type Confidence int

const (
	ConfLow Confidence = iota
	ConfMedium
	ConfHigh
)

var confNames = map[Confidence]string{
	ConfLow:    "low",
	ConfMedium: "medium",
	ConfHigh:   "high",
}

func (c Confidence) String() string {
	if n, ok := confNames[c]; ok {
		return n
	}
	return "unknown"
}

func (c Confidence) MarshalJSON() ([]byte, error) { return json.Marshal(c.String()) }

func (c *Confidence) UnmarshalJSON(b []byte) error {
	var n string
	if err := json.Unmarshal(b, &n); err != nil {
		return err
	}
	for k, v := range confNames {
		if v == n {
			*c = k
			return nil
		}
	}
	return fmt.Errorf("unknown confidence %q", n)
}

// Evidence is one supporting datum behind a finding.
type Evidence struct {
	Label  string    `json:"label"`
	Value  string    `json:"value"`
	Ref    string    `json:"ref,omitempty"`
	Series []float64 `json:"series,omitempty"`
}

// Finding is a conclusion. Body must use the "consistent with" register rather
// than asserting a cause: connect() timing alone cannot prove a SYN was
// dropped. See the confidence calibration notes in analyze.Detect.
type Finding struct {
	ID         string     `json:"id"`
	Probe      string     `json:"probe"`
	Severity   Severity   `json:"severity"`
	Confidence Confidence `json:"confidence"`
	Title      string     `json:"title"`
	Body       string     `json:"body"`
	// Summary is the one-sentence, number-bearing restatement used as the
	// report's verdict line. Title names the problem; Summary says how much of it
	// there is, which is what the reader wants first.
	Summary  string     `json:"summary,omitempty"`
	Evidence []Evidence `json:"evidence,omitempty"`
	Advice   []string   `json:"advice,omitempty"`
	// Priority breaks ties when choosing the primary cause; higher wins.
	Priority int `json:"priority,omitempty"`
}

// New builds a finding with the common fields set.
func New(id, probe string, sev Severity, conf Confidence, title, body string) Finding {
	return Finding{ID: id, Probe: probe, Severity: sev, Confidence: conf, Title: title, Body: body}
}

// WithEvidence appends evidence entries.
func (f Finding) WithEvidence(ev ...Evidence) Finding {
	f.Evidence = append(f.Evidence, ev...)
	return f
}

// WithAdvice appends actionable next steps.
func (f Finding) WithAdvice(a ...string) Finding {
	f.Advice = append(f.Advice, a...)
	return f
}

// WithPriority sets the tie-break priority.
func (f Finding) WithPriority(p int) Finding {
	f.Priority = p
	return f
}

// WithSummary sets the one-line, number-bearing restatement of the finding.
func (f Finding) WithSummary(s string) Finding {
	f.Summary = s
	return f
}

// Ev is a shorthand evidence constructor.
func Ev(label, value string) Evidence { return Evidence{Label: label, Value: value} }

// EvSeries is evidence with the raw samples attached, so the renderer can draw
// them inline next to the claim they support.
func EvSeries(label, value, ref string, series []float64) Evidence {
	return Evidence{Label: label, Value: value, Ref: ref, Series: series}
}
