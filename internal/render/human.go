// Package render turns a model.Report into the two output formats the CLI
// ships: a human-readable diagnosis and a machine-readable JSON dump.
//
// The human renderer is the product. It is opinionated about order: it leads
// with the evidence a person can actually see — the raw samples as a sparkline,
// then the clusters those samples form — before it states a conclusion, because
// seeing two separated strips of samples is what makes "SYN retransmit"
// believable instead of merely asserted.
//
// Renderers are structure-driven. They read the typed model and never hard-code
// a probe's name, so adding a probe never requires touching this package. The
// one piece of computation done here (cluster detection over a sample series) is
// the same pure function the rule engine uses, so the picture the reader sees is
// the picture the conclusion was drawn from.
package render

import (
	"fmt"
	"io"
	"math"
	"strconv"
	"strings"

	"github.com/A015cc/why-slow/internal/analyze"
	"github.com/A015cc/why-slow/internal/model"
)

// defaultWidth is the column budget used when Options.Width is unset.
const defaultWidth = 80

// Options controls human rendering. Width is the target display width in
// columns; zero selects a sensible default.
type Options struct {
	Color bool
	Width int
}

// Human writes the human-readable diagnosis.
func Human(w io.Writer, r *model.Report, opts Options) error {
	if opts.Width <= 0 {
		opts.Width = defaultWidth
	}
	p := newPalette(opts.Color)

	var b strings.Builder
	writeHeader(&b, r)
	writeLatency(&b, r, opts, p)
	writeFindings(&b, r, opts, p)
	writeVerdict(&b, r, opts, p)
	writeProbeErrors(&b, r)

	_, err := io.WriteString(w, b.String())
	return err
}

func blank(b *strings.Builder) {
	if b.Len() > 0 {
		b.WriteByte('\n')
	}
}

func writeHeader(b *strings.Builder, r *model.Report) {
	tool := r.Tool
	if tool == "" {
		tool = "why-slow"
	}
	ver := r.Version
	if ver == "" {
		ver = "dev"
	}
	fmt.Fprintf(b, "%s %s\n", tool, ver)

	t := &kvTable{}
	if r.Target != "" {
		t.add("target", r.Target)
	}
	t.add("samples", strconv.Itoa(sampleCount(r)))
	if r.DurationMS > 0 {
		t.add("duration", fmtDur(r.DurationMS))
	}
	if !r.StartedAt.IsZero() {
		t.add("started", r.StartedAt.UTC().Format("2006-01-02 15:04:05 UTC"))
	}
	for _, line := range t.render() {
		fmt.Fprintf(b, "  %s\n", line)
	}
}

// writeLatency renders one block per observation that carries raw samples.
func writeLatency(b *strings.Builder, r *model.Report, opts Options, p palette) {
	for _, o := range r.Observations {
		if len(o.Series) == 0 {
			continue
		}
		blank(b)
		writeSeries(b, r, o, opts, p)
	}
}

func writeSeries(b *strings.Builder, r *model.Report, o model.Observation, opts Options, p palette) {
	label := strings.ToUpper(o.Key)
	if label == "" {
		label = "SERIES"
	}
	subject := o.Subject
	if ip := firstMeta(o.Meta, "ip", "addr", "resolved_ip", "remote_ip", "peer", "remote"); ip != "" && !strings.Contains(subject, ip) {
		if subject == "" {
			subject = ip
		} else {
			subject += " (" + ip + ")"
		}
	}

	sorted := analyze.Sort(o.Series)
	p50 := analyze.Percentile(sorted, 50)
	p95 := analyze.Percentile(sorted, 95)

	head := label
	if subject != "" {
		head += "  " + subject
	}
	head += fmt.Sprintf("   n=%d   p50=%s   p95=%s", len(o.Series), fmtDur(p50), fmtDur(p95))
	fmt.Fprintf(b, "%s\n", head)

	const sampleLead = "  samples  "
	avail := opts.Width - runeLen(sampleLead)
	if avail < 8 {
		avail = 8
	}
	fmt.Fprintf(b, "%s%s\n", sampleLead, Sparkline(o.Series, avail))

	if isDurationUnit(o.Unit) {
		writeClusters(b, r, o, analyze.Detect(o.Series, analyze.DefaultOptions()), opts, p)
	}
}

// writeClusters renders the two modes the detector found, then the reading of
// them. The label annotations ("<- baseline RTT") are the whole point: they name
// the shape so the reader does not have to hold numbers in their head.
func writeClusters(b *strings.Builder, r *model.Report, o model.Observation, res analyze.Result, opts Options, p palette) {
	if res.LowN > 0 {
		fmt.Fprintf(b, "  %s   %s   n=%d   IQR %s    <- baseline RTT\n",
			p.cluster("cluster A"), fmtDur(res.BaselineMS), res.LowN, fmtDur(res.LowIQR))
	}
	if res.Signal {
		// Annotate with the ladder rung rather than the raw measured offset: the
		// rung is the round, physically meaningful quantity (1.00s), while the
		// measured cluster centre is already in the first column.
		fmt.Fprintf(b, "  %s   %s   n=%d   IQR %s    <- baseline + %s (%s)\n",
			p.cluster("cluster B"), fmtDur(res.ClusterMS), res.ClusterN, fmtDur(res.ClusterIQR),
			fmtDur(res.RungMS), rungName(res.RungMS))
	}

	for _, line := range wrapText(interpretation(r, o, res), opts.Width-2) {
		fmt.Fprintf(b, "  %s\n", line)
	}
	if res.Signal {
		fmt.Fprintf(b, "  implied SYN loss %.0f%% (%d/%d, 95%% CI %.0f-%.0f%%)   confidence: %s\n",
			res.LossRate*100, res.ClusterN, res.N, res.LossLo*100, res.LossHi*100, res.Confidence)
	}
}

// interpretation prefers the prose a finding already carries about this probe,
// so the summary and the detail agree by construction, and falls back to the
// detector's own reason when there is no finding to quote.
func interpretation(r *model.Report, o model.Observation, res analyze.Result) string {
	for _, f := range r.Findings {
		if f.Probe == o.Probe {
			if body := strings.TrimSpace(f.Body); body != "" {
				return body
			}
		}
	}
	if res.Signal {
		return "the slow samples sit on a TCP retransmission ladder rung, which is consistent with handshake loss rather than server slowness"
	}
	return strings.TrimSpace(res.Reason)
}

func writeFindings(b *strings.Builder, r *model.Report, opts Options, p palette) {
	if len(r.Findings) == 0 {
		return
	}
	blank(b)
	fmt.Fprintf(b, "FINDINGS\n")

	// Sort a copy: the renderer must present worst-first but must not reorder
	// the caller's slice.
	sorted := &model.Report{Findings: append([]model.Finding(nil), r.Findings...)}
	sorted.SortFindings()
	for i, f := range sorted.Findings {
		if i > 0 {
			b.WriteByte('\n')
		}
		writeFinding(b, f, opts, p)
	}
}

func writeFinding(b *strings.Builder, f model.Finding, opts Options, p palette) {
	fmt.Fprintf(b, "  %s %s   [%s, %s confidence]\n", p.sev(f.Severity), f.Title, f.Severity, f.Confidence)

	for _, line := range wrapText(f.Body, opts.Width-6) {
		fmt.Fprintf(b, "      %s\n", line)
	}

	if len(f.Evidence) > 0 {
		fmt.Fprintf(b, "      evidence\n")
		for _, ev := range f.Evidence {
			line := ev.Label
			if ev.Value != "" {
				if line != "" {
					line += ": "
				}
				line += ev.Value
			}
			if ev.Ref != "" {
				line += "  [" + ev.Ref + "]"
			}
			if len(ev.Series) > 0 {
				line += "  " + Sparkline(ev.Series, 32)
			}
			fmt.Fprintf(b, "        %s\n", line)
		}
	}

	if len(f.Advice) > 0 {
		fmt.Fprintf(b, "      advice\n")
		for _, a := range f.Advice {
			for j, ln := range wrapText(a, opts.Width-10) {
				if j == 0 {
					fmt.Fprintf(b, "        -> %s\n", ln)
				} else {
					fmt.Fprintf(b, "           %s\n", ln)
				}
			}
		}
	}
}

func writeVerdict(b *strings.Builder, r *model.Report, opts Options, p palette) {
	v := r.Verdict
	if v.OneLiner == "" && v.PrimaryCause == "" {
		return
	}
	blank(b)
	fmt.Fprintf(b, "VERDICT\n")

	if v.OneLiner != "" {
		marker := p.sev(v.Level)
		lead := "  " + sevMarker(v.Level) + " "
		cont := strings.Repeat(" ", runeLen(lead))
		for i, ln := range wrapText(v.OneLiner, opts.Width-runeLen(lead)) {
			if i == 0 {
				fmt.Fprintf(b, "%s%s %s\n", "  ", marker, ln)
			} else {
				fmt.Fprintf(b, "%s%s\n", cont, ln)
			}
		}
	}
	if v.PrimaryCause != "" {
		fmt.Fprintf(b, "    primary cause: %s\n", v.PrimaryCause)
	}
}

func writeProbeErrors(b *strings.Builder, r *model.Report) {
	if len(r.ProbeErrors) == 0 {
		return
	}
	blank(b)
	fmt.Fprintf(b, "PROBE ERRORS\n")
	t := &kvTable{}
	for _, pe := range r.ProbeErrors {
		t.add(pe.Probe, pe.Err)
	}
	for _, line := range t.render() {
		fmt.Fprintf(b, "  %s\n", line)
	}
}

// isDurationUnit reports whether a series is a latency (time) series, which is
// the only kind a retransmission-ladder reading applies to.
func isDurationUnit(u string) bool {
	switch strings.ToLower(strings.TrimSpace(u)) {
	case "ms", "millisecond", "milliseconds",
		"s", "sec", "secs", "second", "seconds",
		"us", "µs", "microsecond", "microseconds":
		return true
	}
	return false
}

// sampleCount totals the individual measurements in a report: a series
// observation contributes one per sample, anything else contributes one.
func sampleCount(r *model.Report) int {
	n := 0
	for _, o := range r.Observations {
		if len(o.Series) > 0 {
			n += len(o.Series)
		} else {
			n++
		}
	}
	return n
}

// fmtDur formats a duration given in milliseconds, choosing a unit and a
// precision that keep the number short and the significant digits intact.
func fmtDur(ms float64) string {
	if math.IsNaN(ms) || math.IsInf(ms, 0) {
		return "n/a"
	}
	a := math.Abs(ms)
	switch {
	case a >= 1000:
		return strconv.FormatFloat(ms/1000, 'f', 2, 64) + "s"
	case a >= 1:
		return strconv.FormatFloat(math.Round(ms*10)/10, 'f', -1, 64) + "ms"
	default:
		return strconv.FormatFloat(math.Round(ms*100)/100, 'f', -1, 64) + "ms"
	}
}

// rungName names the retransmission ladder rung by its 1-based position, which
// is how the ladder is discussed ("rung 1"). An unrecognised rung still gets a
// neutral label rather than an empty one.
func rungName(rung float64) string {
	for _, ladder := range [][]float64{analyze.LadderModern, analyze.LadderLegacy} {
		for i, v := range ladder {
			if v == rung {
				return fmt.Sprintf("ladder rung %d", i+1)
			}
		}
	}
	return "retransmission rung"
}

func firstMeta(m map[string]string, keys ...string) string {
	for _, k := range keys {
		if v := strings.TrimSpace(m[k]); v != "" {
			return v
		}
	}
	return ""
}

// wrapText greedily wraps s on spaces to at most width columns. Words longer
// than width are left intact rather than split.
func wrapText(s string, width int) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	if width < 1 {
		width = 1
	}
	var lines []string
	cur := ""
	for _, w := range strings.Fields(s) {
		switch {
		case cur == "":
			cur = w
		case runeLen(cur)+1+runeLen(w) <= width:
			cur += " " + w
		default:
			lines = append(lines, cur)
			cur = w
		}
	}
	if cur != "" {
		lines = append(lines, cur)
	}
	return lines
}
