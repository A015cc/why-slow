package verdict

import (
	"fmt"

	"github.com/A015cc/why-slow/internal/model"
)

// natSubj is the subject the nat probe uses for host-wide conclusions.
const natSubj = "nat"

// natRules reads the public-address and NAT evidence.
//
// The probe deliberately refuses to claim more than it can see, and these rules
// keep that promise at the reporting layer: "unknown" is reported as unknown,
// with the reason attached, rather than rounded to the reassuring answer.
// Sending someone to configure port forwarding behind carrier NAT wastes an
// evening.
//
// Note the two subjects: the probe files its NAT conclusion under "nat" and its
// address measurements under "public". Reading a public.* key under "nat" finds
// nothing and fails silently, so the split is called out here.
func natRules(st *model.State) []model.Finding {
	var out []model.Finding

	switch cgnat := textOf(st, probeNAT, keyNatCGNAT, natSubj); cgnat {
	case "true":
		reason := textOf(st, probeNAT, keyNatReason, natSubj)
		ev := []model.Evidence{}
		if reason != "" {
			ev = append(ev, model.Ev("what was observed", reason))
		}
		if v4 := textOf(st, probeNAT, keyPublicV4, publicSubject); v4 != "" {
			ev = append(ev, model.Ev("public IPv4", v4))
		}
		out = append(out, model.New(
			"nat.cgnat", probeNAT,
			model.SevNotice, model.ConfHigh,
			"Carrier-grade NAT detected",
			"At least one address in the path lies in 100.64.0.0/10, the range reserved "+
				"for carrier-grade NAT. The practical consequence is that an inbound "+
				"connection cannot be established by forwarding a port, because the ISP is "+
				"translating the address as well as the router.",
		).WithSummary(
			"Carrier-grade NAT is in the path: inbound port forwarding cannot work.",
		).WithEvidence(ev...).WithAdvice(
			"Use an outbound-initiated tunnel (WireGuard, Tailscale) or a relay for inbound access.",
			"Do not spend time on router port-forwarding rules: they cannot affect this.",
		).WithPriority(50))

	case "unknown":
		reason := textOf(st, probeNAT, keyNatReason, natSubj)
		ev := []model.Evidence{}
		if reason != "" {
			ev = append(ev, model.Ev("what was observable", reason))
		}
		out = append(out, model.New(
			"nat.unknown", probeNAT,
			model.SevInfo, model.ConfLow,
			"Whether carrier NAT is in the path could not be determined",
			"Nothing observed rules carrier-grade NAT either in or out. A host cannot see "+
				"its router's WAN address, so NAT at the ISP and NAT at the router are not "+
				"distinguishable from here — this is a limit on what is observable, not a "+
				"measurement that came back empty.",
		).WithSummary(
			"Whether the ISP is doing NAT could not be determined from this host.",
		).WithEvidence(ev...).WithPriority(15))
	}

	// A failed public-IP lookup has to be reported rather than quietly omitted.
	// A report that simply lacks a public address reads as "there was none to
	// report", when the truth is that the measurement did not happen and every
	// conclusion resting on it is unavailable. Silence here is the failure mode
	// this rule exists to prevent.
	if msg := textOf(st, probeNAT, keyPublicError, publicSubject); msg != "" {
		out = append(out, model.New(
			"nat.public_lookup_failed", probeNAT,
			model.SevNotice, model.ConfHigh,
			"The public address could not be determined",
			"None of the public-IP echo services answered. This probe deliberately bypasses "+
				"the system proxy so that the address it reports is this host's own rather "+
				"than a proxy's — which also means that on a network where those services "+
				"are reachable only through a proxy, every one of them will fail. Either "+
				"way the public address is missing, not absent.",
		).WithSummary(
			"The public address could not be determined: no echo provider answered.",
		).WithEvidence(model.Ev("error", msg)).WithAdvice(
			"Check whether the echo services are reachable from this host without a proxy.",
			"The NAT conclusion below rests on local and gateway addresses only.",
		).WithPriority(35))
	}

	// Two independent providers disagreeing is itself the finding — but only when
	// two actually answered. The probe encodes a lone answer as "not agreed",
	// because one source cannot corroborate anything, so agreement alone cannot
	// tell a genuine disagreement from an absent second opinion. Reading the
	// second as the first accuses the network of interception on the strength of a
	// single measurement, which is the exact failure this tool exists to avoid.
	answers := int(numOf(st, probeNAT, keyPublicAnswers, publicSubject))
	prov := textOf(st, probeNAT, keyPublicProv, publicSubject)
	v4 := textOf(st, probeNAT, keyPublicV4, publicSubject)

	switch {
	case answers >= 2 && textOf(st, probeNAT, keyPublicAgree, publicSubject) == "false":
		ev := []model.Evidence{model.Ev("providers", prov)}
		if v4 != "" {
			ev = append(ev, model.Ev("reported address", v4))
		}
		out = append(out, model.New(
			"nat.providers_disagree", probeNAT,
			model.SevNotice, model.ConfMedium,
			"Two public-address providers disagree",
			"Independent public-IP services returned different addresses. Agreement "+
				"between independent sources is the expected case, so a disagreement usually "+
				"means something on the path is intercepting or rewriting the requests rather "+
				"than the address changing between them.",
		).WithSummary(
			"Two public-IP services returned different addresses, which points at interception.",
		).WithEvidence(ev...).WithAdvice(
			"Check for a transparent proxy, a hijacking resolver, or an accelerator driver "+
				"intercepting HTTP traffic.",
		).WithPriority(45))

	case answers == 1:
		// The address is real but uncorroborated, and saying so is the point: the
		// cross-check that would catch a proxy reporting someone else's address
		// simply did not run.
		out = append(out, model.New(
			"nat.public_uncorroborated", probeNAT,
			model.SevInfo, model.ConfHigh,
			"The public address was not corroborated",
			fmt.Sprintf("Only one of the echo services answered (%s), so the address it "+
				"reported was never checked against a second, independent source. The address "+
				"is probably right; the cross-check that would have caught it being wrong did "+
				"not happen.", prov),
		).WithSummary(
			"Only one public-IP service answered, so the address is uncorroborated.",
		).WithEvidence(
			model.Ev("providers that answered", prov),
			model.Ev("reported address", v4),
		).WithPriority(25))
	}
	return out
}
