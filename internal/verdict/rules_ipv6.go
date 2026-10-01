package verdict

import (
	"fmt"

	"github.com/A015cc/why-slow/internal/model"
)

// ipv6Subj is the fixed subject the ipv6 probe uses for host-wide facts.
const ipv6Subj = "ipv6"

// ipv6Rules reports whether IPv6 is configured or actually usable.
//
// The distinction is the entire reason the probe dials a real endpoint instead
// of listing addresses, and the two states need opposite advice: one is "turn
// IPv6 on because you are losing a direct path", the other is "your IPv6 is
// broken, stop preferring it". Collapsing them into "IPv6: present/absent" would
// give the wrong advice half the time.
func ipv6Rules(st *model.State) []model.Finding {
	if !has(st, probeIPv6, keyV6Reachable, ipv6Subj) {
		return nil
	}
	reachable := isTrue(st, probeIPv6, keyV6Reachable, ipv6Subj)
	anyGlobal := isTrue(st, probeIPv6, keyV6AnyGlobal, ipv6Subj)
	classes := st.Texts(probeIPv6, keyV6Classes)

	ev := []model.Evidence{
		model.Ev("IPv6 endpoint reachable", fmt.Sprintf("%t", reachable)),
		model.Ev("global unicast address present", fmt.Sprintf("%t", anyGlobal)),
	}
	for _, name := range sortedKeys(classes) {
		ev = append(ev, model.Ev("addresses on "+name, classes[name]))
	}
	// A default-route observation is only written where a platform source
	// exists. Its absence means "unknown", and asserting "no default route" on a
	// platform that simply cannot read one would be a fabrication — the same
	// honesty rule the path probe applies to the gateway.
	if has(st, probeIPv6, keyV6Default, ipv6Subj) {
		ev = append(ev, model.Ev("default IPv6 route", textOf(st, probeIPv6, keyV6Default, ipv6Subj)))
	}
	if msg := textOf(st, probeIPv6, keyV6Error, ipv6Subj); msg != "" {
		ev = append(ev, model.Ev("dial error", msg))
	}

	switch {
	case !reachable && anyGlobal:
		return []model.Finding{model.New(
			"ipv6.no_path", probeIPv6,
			model.SevWarning, model.ConfHigh,
			"IPv6 has an address but no working path",
			"An interface holds a global unicast IPv6 address, yet a real IPv6 endpoint could "+
				"not be reached. An address proves only that something advertised a prefix: not "+
				"that the prefix is routed, not that the upstream filters it correctly, and not "+
				"that the address is still valid. The address exists; the path does not.",
		).WithSummary(
			"IPv6 holds a global address but cannot reach the internet over it.",
		).WithEvidence(ev...).WithAdvice(
			"Check address and prefix lifetimes, and prefix delegation, on the router.",
			"Treat IPv6 as unavailable when configuring tunnels or peer-to-peer tools until this is fixed.",
		).WithPriority(75)}

	case !reachable:
		return []model.Finding{model.New(
			"ipv6.unusable", probeIPv6,
			model.SevNotice, model.ConfHigh,
			"IPv6 is not usable on this host",
			"No interface holds a global unicast IPv6 address and a real IPv6 endpoint could "+
				"not be reached, so nothing here is using IPv6. Worth establishing rather than "+
				"assuming, because IPv6 is off by default on many consumer routers — and tools "+
				"that would have taken a direct path quietly fall back to a relay without it.",
		).WithSummary(
			"IPv6 is off or absent: no global address, and no reachable IPv6 endpoint.",
		).WithEvidence(ev...).WithAdvice(
			"Enable IPv6 on the router if the ISP supports it; a direct path is often markedly " +
				"faster than the relay a peer-to-peer tool falls back to.",
		).WithPriority(40)}
	}
	return nil
}
