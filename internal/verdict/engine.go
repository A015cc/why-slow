// Package verdict turns observations into conclusions.
//
// Rules here are pure functions over model.State: no network, no clock, no OS
// calls. That is not purity for its own sake. It means the entire conclusion
// layer can be exercised as data → findings, which is the only affordable way to
// test the cases that matter most — the ones where a rule must stay silent. A
// detector that fires when it should not is worse than one that misses, because
// it sends someone to fix a thing that was never broken.
//
// Two conventions keep the output honest:
//
//   - Confidence is orthogonal to Severity. "This is serious and we are not
//     sure" is a legitimate, common answer, and the report has to be able to say
//     it rather than rounding it to certainty in one direction.
//   - Body prose uses the "consistent with" register. connect() timing cannot
//     prove a SYN was dropped: a middlebox, a saturated accept queue and a
//     server softirq stall all leave a similar shape. The wording is the
//     guarantee that the tool does not claim more than it measured, and it is
//     the entire difference between this and a ping tool.
package verdict

import (
	"fmt"
	"math"
	"sort"
	"strings"

	"github.com/A015cc/why-slow/internal/model"
)

// Rule reads a State and returns whatever findings the evidence supports.
type Rule func(*model.State) []model.Finding

// Rules returns the rule set in evaluation order.
func Rules() []Rule {
	return []Rule{
		latencyRules,
		dnsRules,
		compareRules,
		pathRules,
		natRules,
		ipv6Rules,
		crossRules,
	}
}

// Run applies every rule and returns the findings, worst first.
func Run(st *model.State) []model.Finding {
	r := &model.Report{}
	for _, rule := range Rules() {
		r.Findings = append(r.Findings, rule(st)...)
	}
	r.SortFindings()
	return r.Findings
}

// causeLabels maps a finding ID to the short phrase reported as the primary
// cause. A missing entry falls back to the finding's ID, so adding a rule
// degrades the wording rather than breaking the run; TestCauseLabelsCoverRules
// keeps the table honest.
var causeLabels = map[string]string{
	"latency.syn_retransmit_ladder":    "handshake packet loss",
	"latency.all_handshakes_timed_out": "no handshake completed at all",
	"latency.port_closed":              "the service is not listening",
	"latency.heavy_truncation":         "handshakes are being dropped",
	"latency.some_refused":             "some attempts were refused",
	"latency.slow_dns":                 "slow name resolution",
	"latency.compare_no_difference":    "no real difference between the targets",
	"latency.compare_difference":       "a real difference between the targets",
	"latency.compare_underpowered":     "not enough usable pairs to compare",
	"path.egress_virtual":              "traffic leaves through a tunnel",
	"path.gateway_cgnat":               "the local gateway is behind carrier NAT",
	"nat.cgnat":                        "carrier-grade NAT",
	"nat.providers_disagree":           "a proxy is rewriting the public address",
	"nat.unknown":                      "the NAT situation could not be determined",
	"nat.public_lookup_failed":         "the public address could not be measured",
	"nat.public_uncorroborated":        "the public address was not corroborated",
	"ipv6.unusable":                    "IPv6 is off or absent",
	"ipv6.no_path":                     "IPv6 has an address but no working path",
	"cross.ladder_through_tunnel":      "handshake loss measured through a tunnel",
	"cross.tunnel_down":                "the tunnel appears to be down",
	"cross.ipv6_relay":                 "IPv6 is off, so a tunnel is relaying",
}

// Verdict summarises findings into the one-line answer to "why is it slow".
//
// It sorts its own copy rather than trusting the caller: the primary cause is
// whichever finding came out worst, and a verdict that depended on callers
// remembering to sort first would be wrong exactly once, quietly.
func Verdict(findings []model.Finding) model.Verdict {
	if len(findings) == 0 {
		return model.Verdict{
			Level:    model.SevInfo,
			OneLiner: "Nothing in these measurements points at a problem.",
		}
	}
	r := &model.Report{Findings: append([]model.Finding(nil), findings...)}
	r.SortFindings()
	top := r.Findings[0]

	one := top.Summary
	if one == "" {
		one = top.Body
	}
	if one == "" {
		one = top.Title
	}
	cause := causeLabels[top.ID]
	if cause == "" {
		cause = top.ID
	}
	return model.Verdict{Level: top.Severity, PrimaryCause: cause, OneLiner: one}
}

// numOf returns an observation's scalar value, or zero when it is absent. It is
// for counters the probes always emit as a group, where absent really does mean
// zero; anything where absent means "unknown" must be read with State.One so the
// difference survives.
func numOf(st *model.State, probe, key, subject string) float64 {
	v, _ := st.Num(probe, key, subject)
	return v
}

// textOf returns an observation's text value, or "" when absent.
func textOf(st *model.State, probe, key, subject string) string {
	v, _ := st.TextOf(probe, key, subject)
	return v
}

// isTrue reports whether a probe-recorded boolean observation is set. The probes
// encode booleans as the strings "true"/"false", and rules compare them
// literally so that a missing observation stays distinguishable from a false
// one.
func isTrue(st *model.State, probe, key, subject string) bool {
	v, ok := st.TextOf(probe, key, subject)
	return ok && v == "true"
}

// has reports whether an exact observation exists, which is how a rule tells
// "the probe says no" from "the probe could not tell".
func has(st *model.State, probe, key, subject string) bool {
	return st.Has(probe, key, subject)
}

// metaOf returns one metadata entry from an observation, used to quote a probe's
// own parameters back as evidence.
func metaOf(st *model.State, probe, key, subject, name string) string {
	o, ok := st.One(probe, key, subject)
	if !ok || o.Meta == nil {
		return ""
	}
	return o.Meta[name]
}

// fmtMS renders a millisecond value at the precision a reader needs: tenths for
// sub-10ms numbers, whole milliseconds to 1s, seconds above that.
func fmtMS(ms float64) string {
	switch {
	case math.IsNaN(ms):
		return "n/a"
	case ms >= 1000:
		return fmt.Sprintf("%.2fs", ms/1000)
	case ms >= 10:
		return fmt.Sprintf("%.0fms", ms)
	default:
		return fmt.Sprintf("%.1fms", ms)
	}
}

// fmtPct renders a 0..1 fraction as a percentage, dropping the decimal when the
// value is effectively whole — "10%" reads better than "10.0%".
func fmtPct(f float64) string {
	p := f * 100
	if math.Abs(p-math.Round(p)) < 0.05 {
		return fmt.Sprintf("%.0f%%", p)
	}
	return fmt.Sprintf("%.1f%%", p)
}

// joinRungs renders ladder rungs as a human list.
func joinRungs(rungs []float64) string {
	parts := make([]string, 0, len(rungs))
	for _, r := range rungs {
		parts = append(parts, fmtMS(r))
	}
	return strings.Join(parts, ", ")
}

// sortedKeys returns a map's keys in sorted order. Rules that iterate a
// per-subject map use it so the report is identical between runs: Go randomises
// map iteration, and a diagnosis that names a different interface or tunnel each
// time it is run is not reproducible.
func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
