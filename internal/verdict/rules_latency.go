package verdict

import (
	"fmt"

	"github.com/A015cc/why-slow/internal/analyze"
	"github.com/A015cc/why-slow/internal/model"
)

// minComparePairs is the fewest surviving A/B pairs that can support a
// comparison. Below this the sign test has so little power that "no difference
// found" would mean "not looked hard enough", which is a different statement and
// must not be dressed up as the first one.
const minComparePairs = 8

// latencyRules reads the TCP handshake measurements.
//
// It walks the subjects that were *attempted* rather than the subjects that
// produced a usable series, because a target where every attempt failed is the
// single most important thing this probe can report — and that target has no
// series at all. Iterating over series would skip precisely the failures worth
// shouting about.
func latencyRules(st *model.State) []model.Finding {
	var out []model.Finding
	for _, subject := range st.Subjects(probeLatency, keyAttempts) {
		out = append(out, completenessFindings(st, subject)...)
		if series := st.Series(probeLatency, keyConnect, subject); len(series) > 0 {
			if f, ok := ladderFinding(subject, series); ok {
				out = append(out, f)
			}
		}
	}
	return out
}

// completenessFindings reports how many handshake attempts actually completed,
// which the cluster detector cannot see: truncated samples are deliberately kept
// out of the series, so without this rule a target that swallowed 40% of its
// handshakes would look like a clean measurement with fewer samples.
func completenessFindings(st *model.State, subject string) []model.Finding {
	attempts := numOf(st, probeLatency, keyAttempts, subject)
	if attempts <= 0 {
		return nil
	}
	truncated := numOf(st, probeLatency, keyTruncated, subject)
	refused := numOf(st, probeLatency, keyRefused, subject)
	other := numOf(st, probeLatency, keyDialErrors, subject)
	timeout := metaOf(st, probeLatency, keyAttempts, subject, "timeout_ms")

	counts := []model.Evidence{
		model.Ev("attempts", fmt.Sprintf("%d", int(attempts))),
		model.Ev("timed out", fmt.Sprintf("%d", int(truncated))),
		model.Ev("refused", fmt.Sprintf("%d", int(refused))),
	}
	if other > 0 {
		counts = append(counts, model.Ev("other errors", fmt.Sprintf("%d", int(other))))
	}
	if timeout != "" {
		counts = append(counts, model.Ev("dial timeout", timeout+"ms"))
	}

	switch {
	case truncated >= attempts:
		return []model.Finding{model.New(
			"latency.all_handshakes_timed_out", probeLatency,
			model.SevCritical, model.ConfHigh,
			"Every handshake attempt timed out",
			"Not one TCP handshake to this address completed inside the dial timeout. Silence "+
				"on every attempt is consistent with the port being filtered, the host being "+
				"unreachable, or the tunnel carrying this traffic being down.",
		).WithSummary(fmt.Sprintf(
			"All %d handshake attempts to %s timed out with no response.", int(attempts), subject,
		)).WithEvidence(counts...).WithAdvice(
			"Check that the service is listening and that no firewall is dropping the port.",
			"If this machine sends traffic through a tunnel or accelerator, confirm it is up.",
			"Try a known-good target to separate \"this port is closed\" from \"this machine has no network\".",
		).WithPriority(95)}

	case refused >= attempts:
		// Worth its own finding precisely because it *isn't* a network problem.
		// Without it, a closed port looks like a broken path and sends the reader
		// looking in the wrong place.
		return []model.Finding{model.New(
			"latency.port_closed", probeLatency,
			model.SevNotice, model.ConfHigh,
			"The host answered, but the port is closed",
			fmt.Sprintf("Every attempt was answered with a reset (ECONNREFUSED) rather than "+
				"silence, so %s is reachable and the network path is working — nothing is "+
				"listening on that port. This is not a link problem, and no amount of network "+
				"tuning will change it.", subject),
		).WithSummary(fmt.Sprintf(
			"%s is reachable but refused all %d connections: nothing is listening on that port.",
			subject, int(attempts),
		)).WithEvidence(counts...).WithAdvice(
			"Confirm the port number, and that the service is running and bound to this interface.",
		).WithPriority(85)}

	case truncated >= 0.3*attempts:
		return []model.Finding{model.New(
			"latency.heavy_truncation", probeLatency,
			model.SevWarning, model.ConfMedium,
			"A large share of handshakes never completed",
			fmt.Sprintf("%d of %d attempts produced no answer at all before the deadline. Those "+
				"samples are excluded from the timing series rather than recorded as slow ones — "+
				"so the distribution below describes only the attempts that succeeded, and it "+
				"understates how bad the path is.", int(truncated), int(attempts)),
		).WithSummary(fmt.Sprintf(
			"%d of %d handshake attempts to %s got no response before the timeout.",
			int(truncated), int(attempts), subject,
		)).WithEvidence(counts...).WithAdvice(
			"Raise -timeout to see whether these attempts eventually complete, which separates "+
				"a slow path from a filtered one.",
			"Look for a middlebox or firewall dropping handshakes on this route.",
		).WithPriority(80)}

	case refused > 0:
		return []model.Finding{model.New(
			"latency.some_refused", probeLatency,
			model.SevInfo, model.ConfHigh,
			"Some attempts were refused",
			fmt.Sprintf("%d of %d attempts were reset rather than ignored, which points at an "+
				"intermittently available listener rather than at the network path.",
				int(refused), int(attempts)),
		).WithSummary(fmt.Sprintf(
			"%d of %d attempts to %s were refused.", int(refused), int(attempts), subject,
		)).WithEvidence(counts...).WithPriority(30)}
	}
	return nil
}

// ladderFinding is the flagship rule: a cluster of samples landing on a TCP
// retransmission ladder rung.
//
// The claim is deliberately narrow. Ladder alignment is strong evidence, because
// the initial RTO is quantized by the RFC rather than chosen by the server, but
// it is still evidence about a *shape*. A middlebox dropping handshakes, a
// saturated accept queue and a server stall can all leave something similar, so
// the finding says "consistent with" and the confidence axis carries the rest.
func ladderFinding(subject string, series []float64) (model.Finding, bool) {
	res := analyze.Detect(series, analyze.DefaultOptions())
	if !res.Signal {
		return model.Finding{}, false
	}

	body := fmt.Sprintf(
		"%d of %d handshake samples sit at about %s, roughly %s above the %s baseline. That "+
			"offset matches a rung of the TCP retransmission backoff ladder (an initial RTO of "+
			"1s on Linux and Windows 10/11, giving cumulative rungs of %s), and the ladder is "+
			"quantized: a genuinely slow server produces a shifted or smeared distribution, not "+
			"one pinned to baseline plus exactly %s. This is consistent with a retransmitted "+
			"handshake — handshake loss — rather than server slowness.",
		res.ClusterN, res.N, fmtMS(res.ClusterMS), fmtMS(res.RungMS), fmtMS(res.BaselineMS),
		joinRungs(analyze.LadderModern), fmtMS(res.RungMS),
	)

	evidence := []model.Evidence{
		model.Ev("baseline", fmt.Sprintf("%s (n=%d, IQR %s)", fmtMS(res.BaselineMS), res.LowN, fmtMS(res.LowIQR))),
		model.EvSeries(
			fmt.Sprintf("stalled cluster at %s", fmtMS(res.ClusterMS)),
			fmt.Sprintf("n=%d, IQR %s", res.ClusterN, fmtMS(res.ClusterIQR)),
			keyConnect, clusterSamples(series, res.HighFlags),
		),
		model.Ev("ladder rungs matched", joinRungs(res.Occupied)),
		model.Ev("implied handshake loss", fmt.Sprintf("%s (%d/%d, 95%% CI %s-%s)",
			fmtPct(res.LossRate), res.ClusterN, res.N, fmtPct(res.LossLo), fmtPct(res.LossHi))),
		model.Ev("arrangement in time", fmt.Sprintf("%s (runs z=%.2f)", res.Temporal, res.RunsZ)),
	}
	if len(res.Occupied) >= 2 {
		evidence = append(evidence, model.Ev("note",
			"two separate rungs are occupied, which a merely slow server cannot produce"))
	}

	advice := []string{
		"Check for a middlebox, firewall or load balancer dropping TCP handshakes on this path.",
	}
	if res.N < 60 {
		advice = append(advice,
			"Re-run with `-n 80` to tighten the loss estimate; the confidence interval on this sample count is wide.")
	}
	advice = append(advice,
		"If the path is lossy and you control the transport, prefer one that treats loss as a "+
			"congestion signal (QUIC/Hysteria2) over a single long-lived TCP connection, which "+
			"backoff makes quadratically worse.")

	return model.New(
		"latency.syn_retransmit_ladder", probeLatency,
		model.SevWarning, res.Confidence,
		"Handshake stalls look like SYN retransmits",
		body,
	).WithSummary(fmt.Sprintf(
		"About %s of handshake attempts needed a retransmit, adding roughly %s to those connections.",
		fmtPct(res.LossRate), fmtMS(res.RungMS),
	)).WithEvidence(evidence...).WithAdvice(advice...).WithPriority(100), true
}

// clusterSamples extracts the samples belonging to the high mode, in temporal
// order, for the sparkline drawn next to the claim.
func clusterSamples(series []float64, flags []bool) []float64 {
	var out []float64
	for i, v := range series {
		if i < len(flags) && flags[i] {
			out = append(out, v)
		}
	}
	return out
}

// dnsRules reports a slow resolver.
//
// This rule exists because the probe went to the trouble of separating the
// lookup from the handshake. Without a rule here that separation would be
// invisible, and the reader would have no way to tell a slow resolver from a
// slow path — the exact confusion the split was built to remove.
func dnsRules(st *model.State) []model.Finding {
	var out []model.Finding
	for _, subject := range st.Subjects(probeLatency, keyDNSLookup) {
		ms := numOf(st, probeLatency, keyDNSLookup, subject)
		var sev model.Severity
		switch {
		case ms >= 1000:
			sev = model.SevWarning
		case ms >= 400:
			sev = model.SevNotice
		default:
			continue
		}
		addresses := metaOf(st, probeLatency, keyDNSLookup, subject, "addresses")
		out = append(out, model.New(
			"latency.slow_dns", probeLatency, sev, model.ConfHigh,
			"Name resolution is slow",
			fmt.Sprintf("Resolving %s took %s. Every handshake timing in this report was measured "+
				"against the resolved address, so none of it includes this time — a slow resolver "+
				"and a lossy path are separate problems with separate fixes, and a single blended "+
				"connect time would have hidden which one you have.", subject, fmtMS(ms)),
		).WithSummary(fmt.Sprintf(
			"Name resolution took %s before the first connection was even attempted.", fmtMS(ms),
		)).WithEvidence(
			model.Ev("lookup", fmtMS(ms)),
			model.Ev("resolved to", addresses),
		).WithAdvice(
			"Point the resolver at a nearer or faster server and re-measure.",
			"Check whether the resolver's own queries are being sent through a proxy or tunnel, "+
				"which would add a round trip to every lookup.",
		).WithPriority(70))
	}
	return out
}

// compareRules reports on the interleaved A/B comparison.
//
// A large p-value is treated as a *finding*, not as the absence of one. It is the
// result that stops someone acting on a difference that was never there — and it
// is the outcome the interleaved design was built to produce, so burying it in
// silence would waste the most useful thing the comparison knows.
func compareRules(st *model.State) []model.Finding {
	var out []model.Finding
	for _, subject := range st.Subjects(probeLatency, keyABPValue) {
		pairs := numOf(st, probeLatency, keyABPairs, subject)
		skipped := numOf(st, probeLatency, keyABSkipped, subject)
		summary := textOf(st, probeLatency, keyABSummary, subject)
		labelA := textOf(st, probeLatency, keyABLabelA, subject)
		labelB := textOf(st, probeLatency, keyABLabelB, subject)

		if pairs < minComparePairs {
			out = append(out, model.New(
				"latency.compare_underpowered", probeLatency,
				model.SevInfo, model.ConfLow,
				"Not enough usable pairs to compare these targets",
				fmt.Sprintf("Only %d complete pairs were measured%s, which is too few for the "+
					"paired sign test to say anything. This is not a finding about the two "+
					"targets; it is a statement that the comparison did not run.",
					int(pairs), skippedNote(int(skipped))),
			).WithSummary(fmt.Sprintf(
				"Only %d usable pairs: too few to compare %s with %s.",
				int(pairs), labelA, labelB,
			)).WithAdvice(
				"Increase -pairs, and check that both targets answer consistently.",
			).WithPriority(20))
			continue
		}

		p := numOf(st, probeLatency, keyABPValue, subject)
		delta := numOf(st, probeLatency, keyABMedian, subject)
		ev := []model.Evidence{
			model.Ev("interleaved pairs", fmt.Sprintf("%d", int(pairs))),
			model.Ev("median (B-A)", fmtMS(delta)),
			model.Ev("sign test p", fmt.Sprintf("%.3f", p)),
			model.Ev("summary", summary),
		}
		if skipped > 0 {
			ev = append(ev, model.Ev("pairs dropped", fmt.Sprintf("%d (incomplete side)", int(skipped))))
		}

		if p >= 0.05 {
			out = append(out, model.New(
				"latency.compare_no_difference", probeLatency,
				model.SevInfo, model.ConfHigh,
				"No evidence that these two targets differ",
				fmt.Sprintf("Across %d interleaved pairs the paired sign test gives p = %.3f, so "+
					"these measurements do not support a real difference between %s and %s. That "+
					"is worth trusting over a sequential comparison of the same two targets: "+
					"measuring one for a while and then the other attributes the link's drift "+
					"during the run to whichever target happened to be measured second.",
					int(pairs), p, labelA, labelB),
			).WithSummary(fmt.Sprintf(
				"No real difference between %s and %s (p = %.3f over %d interleaved pairs).",
				labelA, labelB, p, int(pairs),
			)).WithEvidence(ev...).WithAdvice(
				"If a sequential test told you one of these is much faster, re-measure it "+
					"interleaved before changing anything based on it.",
			).WithPriority(25))
			continue
		}

		slower, faster := labelB, labelA
		if delta < 0 {
			slower, faster = labelA, labelB
		}
		out = append(out, model.New(
			"latency.compare_difference", probeLatency,
			model.SevNotice, model.ConfHigh,
			"These two targets really do differ",
			fmt.Sprintf("The paired sign test gives p = %.3f over %d interleaved pairs, so the "+
				"difference survives the interleaving that exists to cancel link drift. %s is "+
				"slower by a median of %s.", p, int(pairs), slower, fmtMS(abs(delta))),
		).WithSummary(fmt.Sprintf(
			"%s is slower than %s by a median of %s (p = %.3f over %d pairs).",
			slower, faster, fmtMS(abs(delta)), p, int(pairs),
		)).WithEvidence(ev...).WithPriority(65))
	}
	return out
}

func skippedNote(skipped int) string {
	if skipped == 0 {
		return ""
	}
	return fmt.Sprintf(" (%d more were dropped for having an incomplete side)", skipped)
}

func abs(f float64) float64 {
	if f < 0 {
		return -f
	}
	return f
}
