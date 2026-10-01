package verdict

import (
	"strings"
	"testing"

	"github.com/A015cc/why-slow/internal/model"
)

const testSubject = "203.0.113.7"

func state(obs ...model.Observation) *model.State {
	st := model.NewState()
	st.Add(obs...)
	return st
}

// cleanSeries is a unimodal handshake distribution: a stable baseline with a few
// milliseconds of jitter, no stalls.
func cleanSeries(n int, base float64) []float64 {
	out := make([]float64, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, base+float64(i%5)-2)
	}
	return out
}

// bimodalSeries puts a deterministic fraction of samples on a retransmission
// rung, spaced evenly through the run.
//
// Even spacing is deliberate. Clumping the stalls together would make the runs
// test call them autocorrelated and downgrade the confidence, which is correct
// behaviour but not what this fixture is testing.
func bimodalSeries(n int, everyNth int, base, rung float64) []float64 {
	out := make([]float64, 0, n)
	for i := 0; i < n; i++ {
		if everyNth > 0 && i%everyNth == everyNth-7 {
			out = append(out, base+rung)
			continue
		}
		out = append(out, base+float64(i%5)-2)
	}
	return out
}

func latencyObs(subject string, series []float64, attempts, truncated, refused float64) []model.Observation {
	obs := []model.Observation{
		model.Num(probeLatency, subject, keyAttempts, "count", attempts, map[string]string{"timeout_ms": "5000"}),
		model.Num(probeLatency, subject, keyTruncated, "count", truncated, nil),
		model.Num(probeLatency, subject, keyRefused, "count", refused, nil),
		model.Num(probeLatency, subject, keyDialErrors, "count", 0, nil),
	}
	if len(series) > 0 {
		obs = append(obs, model.Series(probeLatency, subject, keyConnect, "ms", series, nil))
	}
	return obs
}

func ids(findings []model.Finding) []string {
	out := make([]string, 0, len(findings))
	for _, f := range findings {
		out = append(out, f.ID)
	}
	return out
}

func hasID(findings []model.Finding, id string) bool {
	_, ok := findID(findings, id)
	return ok
}

// The most important test in this package: a healthy measurement must produce
// nothing at all. A rule that fires on clean data sends someone to fix a thing
// that was never broken, which costs more than missing a real problem.
func TestCleanMeasurementProducesNoFindings(t *testing.T) {
	st := state(latencyObs(testSubject, cleanSeries(40, 150), 40, 0, 0)...)
	if got := ids(Run(st)); len(got) != 0 {
		t.Errorf("clean run produced findings %v, want none", got)
	}
	if v := Verdict(nil); v.Level != model.SevInfo {
		t.Errorf("verdict level = %v, want info", v.Level)
	}
}

func TestEmptyStateProducesNoFindings(t *testing.T) {
	if got := ids(Run(model.NewState())); len(got) != 0 {
		t.Errorf("empty state produced findings %v, want none", got)
	}
}

// The flagship: a cluster of handshakes sitting one RTO above the baseline.
func TestLadderFiresOnBimodalSeries(t *testing.T) {
	series := bimodalSeries(40, 10, 150, 1000)
	st := state(latencyObs(testSubject, series, 40, 0, 0)...)

	findings := Run(st)
	f, ok := findID(findings, "latency.syn_retransmit_ladder")
	if !ok {
		t.Fatalf("no ladder finding; got %v", ids(findings))
	}
	if f.Severity != model.SevWarning {
		t.Errorf("severity = %v, want warning", f.Severity)
	}
	if f.Confidence != model.ConfMedium {
		t.Errorf("confidence = %v, want medium for a single occupied rung", f.Confidence)
	}
	if f.Summary == "" {
		t.Error("ladder finding has no Summary, so the verdict line would fall back to the body")
	}
	if len(f.Evidence) == 0 {
		t.Error("ladder finding carries no evidence")
	}
	// The claim must stay in the "consistent with" register: connect() timing
	// cannot prove a SYN was dropped.
	if !contains(f.Body, "consistent with") {
		t.Errorf("body does not hedge its claim:\n%s", f.Body)
	}
}

// A single outlier is not a cluster. This is the false-positive case the
// detector's MinCluster guard exists for.
func TestSingleOutlierIsNotAFinding(t *testing.T) {
	series := cleanSeries(40, 150)
	series[17] = 1150
	st := state(latencyObs(testSubject, series, 40, 0, 0)...)
	findings := Run(st)
	if hasID(findings, "latency.syn_retransmit_ladder") {
		t.Errorf("one outlier produced a ladder finding: %v", ids(findings))
	}
}

func TestAllHandshakesTimedOut(t *testing.T) {
	st := state(latencyObs(testSubject, nil, 40, 40, 0)...)
	f, ok := findID(Run(st), "latency.all_handshakes_timed_out")
	if !ok {
		t.Fatal("total timeout produced no finding")
	}
	if f.Severity != model.SevCritical || f.Confidence != model.ConfHigh {
		t.Errorf("severity/confidence = %v/%v, want critical/high", f.Severity, f.Confidence)
	}
}

// A refused connection is not a broken network, and saying so is the whole
// point of separating it from a timeout.
func TestRefusedIsReportedAsAClosedPortNotAPathProblem(t *testing.T) {
	st := state(latencyObs(testSubject, nil, 40, 0, 40)...)
	f, ok := findID(Run(st), "latency.port_closed")
	if !ok {
		t.Fatal("all-refused run produced no finding")
	}
	if f.Confidence != model.ConfHigh {
		t.Errorf("confidence = %v, want high: the reset is a direct observation", f.Confidence)
	}
	if !contains(f.Title+f.Body, "reachable") {
		t.Errorf("finding does not tell the reader the host is reachable:\n%s\n%s", f.Title, f.Body)
	}
}

// Truncated samples never enter the series, so the detector alone would report a
// clean measurement with fewer samples. The completeness rule is what keeps a
// half-filtered path from looking healthy.
func TestHeavyTruncationIsReportedEvenWithoutAFlaggedCluster(t *testing.T) {
	st := state(latencyObs(testSubject, cleanSeries(26, 150), 40, 14, 0)...)
	if !hasID(Run(st), "latency.heavy_truncation") {
		t.Error("14 of 40 handshakes timing out produced no finding")
	}
}

func TestSlowDNSIsReportedSeparately(t *testing.T) {
	obs := append(latencyObs(testSubject, cleanSeries(40, 150), 40, 0, 0),
		model.Num(probeLatency, "example.com", keyDNSLookup, "ms", 1400, map[string]string{"addresses": testSubject}),
	)
	f, ok := findID(Run(state(obs...)), "latency.slow_dns")
	if !ok {
		t.Fatal("a 1.4s lookup produced no finding")
	}
	if f.Severity != model.SevWarning {
		t.Errorf("severity = %v, want warning", f.Severity)
	}
}

func TestVirtualEgressIsReported(t *testing.T) {
	obs := []model.Observation{
		model.Text(probePath, "vps.example.com", keyEgressVirtual, "true", nil),
		model.Text(probePath, "vps.example.com", keyEgressKind, "Tailscale tunnel", nil),
		model.Text(probePath, "vps.example.com", keyEgressIface, "Tailscale", nil),
	}
	f, ok := findID(Run(state(obs...)), "path.egress_virtual")
	if !ok {
		t.Fatal("virtual egress produced no finding")
	}
	if !contains(f.Summary, "Tailscale") {
		t.Errorf("summary does not name the tunnel: %q", f.Summary)
	}
}

// The cross rule the layering exists for: neither fact is remarkable alone, and
// together they change what the other one means.
func TestLadderThroughATunnelTriggersTheCrossRule(t *testing.T) {
	obs := append(latencyObs(testSubject, bimodalSeries(40, 10, 150, 1000), 40, 0, 0),
		model.Text(probePath, "vps.example.com", keyEgressVirtual, "true", nil),
		model.Text(probePath, "vps.example.com", keyEgressKind, "Tailscale tunnel", nil),
	)
	findings := Run(state(obs...))
	if !hasID(findings, "latency.syn_retransmit_ladder") {
		t.Fatal("expected the ladder finding alongside the cross rule")
	}
	if !hasID(findings, "cross.ladder_through_tunnel") {
		t.Errorf("ladder + tunnel produced no cross finding; got %v", ids(findings))
	}
}

// Without a tunnel, the cross rule must stay quiet — it is a comment on the
// interaction, not a second copy of the ladder finding.
func TestLadderWithoutATunnelHasNoCrossFinding(t *testing.T) {
	st := state(latencyObs(testSubject, bimodalSeries(40, 10, 150, 1000), 40, 0, 0)...)
	if hasID(Run(st), "cross.ladder_through_tunnel") {
		t.Error("cross rule fired with no tunnel in the path")
	}
}

func TestIPv6Unusable(t *testing.T) {
	obs := []model.Observation{
		model.Text(probeIPv6, ipv6Subj, keyV6Reachable, "false", nil),
		model.Text(probeIPv6, ipv6Subj, keyV6AnyGlobal, "false", nil),
		model.Text(probeIPv6, "以太网 4", keyV6Classes, "link-local", nil),
	}
	f, ok := findID(Run(state(obs...)), "ipv6.unusable")
	if !ok {
		t.Fatal("unusable IPv6 produced no finding")
	}
	if !contains(f.Summary, "IPv6") {
		t.Errorf("summary = %q", f.Summary)
	}
}

// An address without a path is the case the probe exists to catch, and it needs
// different advice from "IPv6 is off".
func TestIPv6AddressWithoutAPath(t *testing.T) {
	obs := []model.Observation{
		model.Text(probeIPv6, ipv6Subj, keyV6Reachable, "false", nil),
		model.Text(probeIPv6, ipv6Subj, keyV6AnyGlobal, "true", nil),
		model.Text(probeIPv6, "以太网 4", keyV6Classes, "global unicast", nil),
	}
	findings := Run(state(obs...))
	f, ok := findID(findings, "ipv6.no_path")
	if !ok {
		t.Fatalf("global address with no path produced %v", ids(findings))
	}
	if f.Severity != model.SevWarning {
		t.Errorf("severity = %v, want warning", f.Severity)
	}
	if hasID(findings, "ipv6.unusable") {
		t.Error("both IPv6 findings fired; they describe mutually exclusive states")
	}
}

// A missing default-route observation means "the platform cannot tell us", and
// must not be rendered as "there is no default route".
func TestMissingDefaultRouteIsNotReportedAsAbsent(t *testing.T) {
	obs := []model.Observation{
		model.Text(probeIPv6, ipv6Subj, keyV6Reachable, "false", nil),
		model.Text(probeIPv6, ipv6Subj, keyV6AnyGlobal, "true", nil),
	}
	f, _ := findID(Run(state(obs...)), "ipv6.no_path")
	for _, e := range f.Evidence {
		if contains(e.Label, "default") {
			t.Errorf("evidence claims a default route when none was observed: %q=%q", e.Label, e.Value)
		}
	}
}

func TestCarrierNATIsReported(t *testing.T) {
	obs := []model.Observation{
		model.Text(probeNAT, natSubj, keyNatCGNAT, "true", nil),
		model.Text(probeNAT, natSubj, keyNatReason, "default gateway 100.64.0.1 is in 100.64.0.0/10", nil),
		model.Text(probeNAT, publicSubject, keyPublicV4, "198.51.100.20", nil),
	}
	f, ok := findID(Run(state(obs...)), "nat.cgnat")
	if !ok {
		t.Fatal("carrier NAT produced no finding")
	}
	if joined := strings.Join(f.Advice, " "); !contains(joined, "forwarding") {
		t.Errorf("advice does not warn against port forwarding: %v", f.Advice)
	}
}

// "Unknown" must be reported as unknown. Rounding it to the reassuring answer is
// how someone loses an evening configuring port forwarding behind carrier NAT.
func TestUnknownNATStaysUnknown(t *testing.T) {
	obs := []model.Observation{
		model.Text(probeNAT, natSubj, keyNatCGNAT, "unknown", nil),
		model.Text(probeNAT, natSubj, keyNatReason, "gateway could not be read on this platform", nil),
	}
	f, ok := findID(Run(state(obs...)), "nat.unknown")
	if !ok {
		t.Fatal("unknown NAT produced no finding")
	}
	if f.Confidence != model.ConfLow {
		t.Errorf("confidence = %v, want low", f.Confidence)
	}
}

// A large p-value is the useful result of an interleaved comparison, so it must
// be reported rather than swallowed.
// A failed public-IP lookup must be reported. A report that simply lacks a
// public address reads as "there was none", when the truth is that the
// measurement did not happen.
func TestPublicLookupFailureIsReported(t *testing.T) {
	obs := []model.Observation{
		model.Text(probeNAT, publicSubject, keyPublicAgree, "false", nil),
		model.Text(probeNAT, publicSubject, keyPublicError,
			"nat: no IPv4 public-IP provider answered (cloudflare,ipify,icanhazip)", nil),
		model.Text(probeNAT, natSubj, keyNatCGNAT, "unknown", nil),
		model.Text(probeNAT, natSubj, keyNatReason, "no evidence of carrier NAT", nil),
	}
	f, ok := findID(Run(state(obs...)), "nat.public_lookup_failed")
	if !ok {
		t.Fatal("a total public-IP lookup failure produced no finding")
	}
	if f.Confidence != model.ConfHigh {
		t.Errorf("confidence = %v, want high: the failure is a direct observation", f.Confidence)
	}
	if !contains(f.Body, "proxy") {
		t.Error("the finding does not explain why a proxy-only network would cause this")
	}
}

// One provider answering is not a disagreement. Reporting it as one accuses the
// network of interception on the strength of a single measurement — and this is
// the real shape the probe produces on a network where only one echo service is
// reachable.
func TestSingleProviderIsUncorroboratedNotADisagreement(t *testing.T) {
	obs := []model.Observation{
		model.Num(probeNAT, publicSubject, keyPublicAnswers, "count", 1, nil),
		model.Text(probeNAT, publicSubject, keyPublicAgree, "false", nil),
		model.Text(probeNAT, publicSubject, keyPublicProv, "icanhazip", nil),
		model.Text(probeNAT, publicSubject, keyPublicV4, "198.51.100.20", nil),
	}
	findings := Run(state(obs...))
	if hasID(findings, "nat.providers_disagree") {
		t.Error("a single answering provider was reported as two providers disagreeing")
	}
	if !hasID(findings, "nat.public_uncorroborated") {
		t.Errorf("a lone answering provider produced %v", ids(findings))
	}
}

func TestCompareReportsNoDifferenceAsAFinding(t *testing.T) {
	const subject = "a vs b"
	obs := []model.Observation{
		model.Num(probeLatency, subject, keyABPairs, "count", 20, nil),
		model.Num(probeLatency, subject, keyABSkipped, "count", 0, nil),
		model.Num(probeLatency, subject, keyABPValue, "p", 0.42, nil),
		model.Num(probeLatency, subject, keyABMedian, "ms", 2.1, nil),
		model.Text(probeLatency, subject, keyABLabelA, "a", nil),
		model.Text(probeLatency, subject, keyABLabelB, "b", nil),
		model.Text(probeLatency, subject, keyABSummary, "median(B-A) = +2.1ms, sign test p = 0.420 over 20 pairs", nil),
	}
	f, ok := findID(Run(state(obs...)), "latency.compare_no_difference")
	if !ok {
		t.Fatal("p = 0.42 produced no finding")
	}
	if f.Confidence != model.ConfHigh {
		t.Errorf("confidence = %v, want high", f.Confidence)
	}
	if !contains(f.Body, "drift") {
		t.Error("the finding does not explain why the interleaved result is the trustworthy one")
	}
}

func TestCompareUnderpoweredIsMarkedAsSuch(t *testing.T) {
	const subject = "a vs b"
	obs := []model.Observation{
		model.Num(probeLatency, subject, keyABPairs, "count", 3, nil),
		model.Num(probeLatency, subject, keyABSkipped, "count", 17, nil),
		model.Num(probeLatency, subject, keyABPValue, "p", 0.9, nil),
		model.Text(probeLatency, subject, keyABLabelA, "a", nil),
		model.Text(probeLatency, subject, keyABLabelB, "b", nil),
	}
	findings := Run(state(obs...))
	if !hasID(findings, "latency.compare_underpowered") {
		t.Errorf("3 usable pairs produced %v", ids(findings))
	}
	if hasID(findings, "latency.compare_no_difference") {
		t.Error("too few pairs was reported as evidence of no difference")
	}
	if f, _ := findID(findings, "latency.compare_underpowered"); f.Confidence != model.ConfLow {
		t.Errorf("confidence = %v, want low", f.Confidence)
	}
}

// The verdict must name the worst finding, not the first one it happens to hold.
func TestVerdictPicksTheWorstFindingRegardlessOfInputOrder(t *testing.T) {
	info := model.New("latency.some_refused", probeLatency, model.SevInfo, model.ConfHigh, "t", "b").
		WithSummary("minor")
	critical := model.New("latency.all_handshakes_timed_out", probeLatency, model.SevCritical, model.ConfHigh, "t", "b").
		WithSummary("everything failed")

	for _, order := range [][]model.Finding{{info, critical}, {critical, info}} {
		v := Verdict(order)
		if v.Level != model.SevCritical {
			t.Errorf("verdict level = %v, want critical", v.Level)
		}
		if v.OneLiner != "everything failed" {
			t.Errorf("one-liner = %q, want the worst finding's summary", v.OneLiner)
		}
		if v.PrimaryCause != "no handshake completed at all" {
			t.Errorf("primary cause = %q", v.PrimaryCause)
		}
	}
}

// Every finding a rule can emit needs a human-readable cause label; the fallback
// is the raw ID, which would leak into the report.
func TestCauseLabelsCoverEveryRule(t *testing.T) {
	obs := []model.Observation{}
	obs = append(obs, latencyObs(testSubject, bimodalSeries(40, 10, 150, 1000), 40, 12, 3)...)
	obs = append(obs,
		model.Num(probeLatency, "example.com", keyDNSLookup, "ms", 1400, nil),
		model.Num(probeLatency, "a vs b", keyABPairs, "count", 20, nil),
		model.Num(probeLatency, "a vs b", keyABSkipped, "count", 0, nil),
		model.Num(probeLatency, "a vs b", keyABPValue, "p", 0.42, nil),
		model.Num(probeLatency, "a vs b", keyABMedian, "ms", 2.1, nil),
		model.Text(probeLatency, "a vs b", keyABLabelA, "a", nil),
		model.Text(probeLatency, "a vs b", keyABLabelB, "b", nil),
		model.Text(probePath, "vps.example.com", keyEgressVirtual, "true", nil),
		model.Text(probePath, "vps.example.com", keyEgressKind, "Tailscale tunnel", nil),
		model.Text(probePath, subjectDefault, keyGatewayCGNAT, "true", nil),
		model.Text(probePath, subjectDefault, keyGateway, "100.64.0.1", nil),
		model.Text(probeNAT, natSubj, keyNatCGNAT, "true", nil),
		model.Text(probeNAT, natSubj, keyNatReason, "gateway in 100.64.0.0/10", nil),
		model.Num(probeNAT, publicSubject, keyPublicAnswers, "count", 2, nil),
		model.Text(probeNAT, publicSubject, keyPublicAgree, "false", nil),
		model.Text(probeNAT, publicSubject, keyPublicProv, "a=1.1.1.1 b=2.2.2.2", nil),
		model.Text(probeIPv6, ipv6Subj, keyV6Reachable, "false", nil),
		model.Text(probeIPv6, ipv6Subj, keyV6AnyGlobal, "false", nil),
	)

	findings := Run(state(obs...))
	if len(findings) < 5 {
		t.Fatalf("kitchen-sink state produced only %v; the fixture is not exercising the rules", ids(findings))
	}
	for _, f := range findings {
		if _, ok := causeLabels[f.ID]; !ok {
			t.Errorf("finding %q has no cause label", f.ID)
		}
	}
}

// Two rules that describe mutually exclusive states must never both fire.
func TestMutuallyExclusiveFindings(t *testing.T) {
	st := state(latencyObs(testSubject, nil, 40, 40, 40)...)
	findings := Run(st)
	if hasID(findings, "latency.all_handshakes_timed_out") && hasID(findings, "latency.port_closed") {
		t.Error("a run cannot be both entirely timed out and entirely refused")
	}
}

func contains(haystack, needle string) bool { return strings.Contains(haystack, needle) }
