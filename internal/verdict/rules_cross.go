package verdict

import (
	"fmt"
	"strings"

	"github.com/A015cc/why-slow/internal/model"
)

// crossRules are the rules that need more than one probe, and they are the whole
// reason observations and conclusions are separate layers.
//
// A single probe cannot say "this retransmission pattern may describe the tunnel
// rather than the link": the latency probe has no idea a tunnel is involved, and
// the path probe has no idea the timings are bimodal. Either fact alone is
// unremarkable. Together they change what the other one means, and no amount of
// per-probe cleverness would have surfaced that.
func crossRules(st *model.State) []model.Finding {
	var out []model.Finding

	// The latency findings are recomputed here rather than threaded through from
	// the engine. Detection is a pure function over at most a few hundred samples,
	// so the cost is irrelevant, and deriving them from the same code path is what
	// guarantees a cross rule can never contradict the finding it comments on.
	latencyFindings := latencyRules(st)
	_, ladder := findID(latencyFindings, "latency.syn_retransmit_ladder")
	_, allTimedOut := findID(latencyFindings, "latency.all_handshakes_timed_out")

	tunnelKind, tunneled := anyEgressVirtual(st)

	switch {
	case allTimedOut && tunneled:
		out = append(out, model.New(
			"cross.tunnel_down", probeLatency,
			model.SevWarning, model.ConfMedium,
			"The tunnel carrying this traffic looks down",
			fmt.Sprintf("Every handshake attempt timed out, and at the same time the path probe "+
				"shows egress leaving through %s. When both hold, the simpler reading is that "+
				"the tunnel is not carrying traffic at all — the target may be perfectly "+
				"reachable from outside it, and nothing about the target needs fixing.", tunnelKind),
		).WithSummary(fmt.Sprintf(
			"No handshake completed and egress runs through %s, so the tunnel is the prime suspect.",
			tunnelKind,
		)).WithAdvice(
			"Check the tunnel's own status and logs before investigating the target.",
			"Test the same target from outside the tunnel to confirm it is reachable.",
		).WithPriority(98))

	case ladder && tunneled:
		out = append(out, model.New(
			"cross.ladder_through_tunnel", probeLatency,
			model.SevNotice, model.ConfMedium,
			"The retransmission pattern may describe the tunnel, not the link",
			fmt.Sprintf("The handshake timings show a retransmission ladder, and egress toward "+
				"that target leaves through %s. Each fact is unremarkable alone; together they "+
				"mean the loss may be happening inside the tunnel, in which case the numbers "+
				"describe the tunnel's own congestion control more than the path beneath it, "+
				"and tuning the physical link will not move them.", tunnelKind),
		).WithSummary(fmt.Sprintf(
			"Handshake loss was measured through %s, so it may be the tunnel's loss rather than the link's.",
			tunnelKind,
		)).WithAdvice(
			"Measure inside and outside the tunnel to attribute the loss to one of them.",
		).WithPriority(90))
	}

	// IPv6 being off is the usual reason a peer-to-peer tunnel ends up relaying
	// instead of connecting directly. That is a latency effect of hundreds of
	// milliseconds, and it is completely invisible to a latency measurement taken
	// through the tunnel — which is exactly the kind of conclusion that requires
	// two probes to reach.
	if has(st, probeIPv6, keyV6Reachable, ipv6Subj) &&
		!isTrue(st, probeIPv6, keyV6Reachable, ipv6Subj) &&
		tunneled && relaysWithoutIPv6(tunnelKind) {
		out = append(out, model.New(
			"cross.ipv6_relay", probeIPv6,
			model.SevNotice, model.ConfMedium,
			"IPv6 is off, so this tunnel is probably relaying rather than connecting directly",
			fmt.Sprintf("IPv6 is unusable on this host while egress runs through %s. "+
				"Peer-to-peer tunnels establish a direct path far more often over IPv6, because "+
				"IPv4 is typically behind NAT that neither side can traverse. Without it they "+
				"fall back to a relay, which inserts a long detour — the kind of difference "+
				"that shows up as hundreds of milliseconds and looks like nothing at all when "+
				"you only measure the inside of the tunnel.", tunnelKind),
		).WithSummary(
			"IPv6 is off, so a peer-to-peer tunnel is likely relaying instead of connecting directly.",
		).WithEvidence(
			model.Ev("IPv6 reachable", "false"),
			model.Ev("egress kind", tunnelKind),
		).WithAdvice(
			"Enable IPv6 on the router, then re-measure from both ends to see whether a direct path appears.",
		).WithPriority(85))
	}
	return out
}

// anyEgressVirtual reports whether any probed target egresses through a virtual
// adapter, and names the kind.
//
// Subjects are visited in sorted order so the reported kind is stable between
// runs. Map iteration order is randomised in Go, and a report that names a
// different tunnel on each run would be a nondeterminism bug in the one place
// the output is supposed to be reproducible.
func anyEgressVirtual(st *model.State) (string, bool) {
	virt := st.Texts(probePath, keyEgressVirtual)
	kinds := st.Texts(probePath, keyEgressKind)
	for _, subject := range sortedKeys(virt) {
		if virt[subject] == "true" {
			kind := kinds[subject]
			if kind == "" {
				kind = "a virtual adapter"
			}
			return kind, true
		}
	}
	return "", false
}

// relaysWithoutIPv6 reports whether a virtual adapter's kind is one that is known
// to fall back to a relay when IPv6 is unavailable.
func relaysWithoutIPv6(kind string) bool {
	k := strings.ToLower(kind)
	for _, needle := range []string{"tailscale", "wireguard", "zerotier", "nordlynx", "warp"} {
		if strings.Contains(k, needle) {
			return true
		}
	}
	return false
}

// findID looks a finding up by ID.
func findID(findings []model.Finding, id string) (model.Finding, bool) {
	for _, f := range findings {
		if f.ID == id {
			return f, true
		}
	}
	return model.Finding{}, false
}
