package verdict

import (
	"fmt"

	"github.com/A015cc/why-slow/internal/model"
)

// pathRules reads how traffic leaves the machine.
//
// Egress through a virtual adapter is reported but is not treated as an error:
// following the tunnel is what the traffic genuinely does. The reason it earns a
// finding anyway is that it changes what every other number in the report is
// *about*, and a reader who does not know the traffic is inside a tunnel will
// draw the wrong conclusion from a perfectly correct measurement.
func pathRules(st *model.State) []model.Finding {
	var out []model.Finding

	virt := st.Texts(probePath, keyEgressVirtual)
	kinds := st.Texts(probePath, keyEgressKind)
	for _, subject := range sortedKeys(virt) {
		if virt[subject] != "true" {
			continue
		}
		kind := kinds[subject]
		if kind == "" || kind == "virtual" {
			kind = "a virtual adapter"
		}
		name := textOf(st, probePath, keyEgressIface, subject)
		src := textOf(st, probePath, keyEgressSrcIP, subject)

		ev := []model.Evidence{model.Ev("kind", kind)}
		if name != "" {
			ev = append(ev, model.Ev("egress interface", name))
		}
		if src != "" {
			ev = append(ev, model.Ev("source address", src))
		}

		out = append(out, model.New(
			"path.egress_virtual", probePath,
			model.SevNotice, model.ConfHigh,
			"Traffic to this target leaves through a tunnel",
			fmt.Sprintf("The kernel routes traffic toward %s out through %s, so every timing "+
				"taken along this path measures the tunnel at least as much as the link "+
				"underneath it. That is not a measurement error — it is the path the traffic "+
				"really takes — but it does change what a latency or loss conclusion is about.",
				subject, kind),
		).WithSummary(fmt.Sprintf(
			"Egress to %s goes through %s, so timings describe the tunnel, not the raw link.",
			subject, kind,
		)).WithEvidence(ev...).WithAdvice(
			"Characterise the link with a target outside the tunnel, and the tunnel with its own far end.",
			"Do not tune the physical link to fix a number that came from inside the tunnel.",
		).WithPriority(60))
	}

	// A default gateway inside 100.64.0.0/10 is a clean carrier-grade NAT signal,
	// and it settles whether inbound port forwarding can work at all.
	if isTrue(st, probePath, keyGatewayCGNAT, subjectDefault) {
		gw := textOf(st, probePath, keyGateway, subjectDefault)
		out = append(out, model.New(
			"path.gateway_cgnat", probePath,
			model.SevNotice, model.ConfHigh,
			"The local gateway is behind carrier-grade NAT",
			fmt.Sprintf("The default gateway (%s) sits in 100.64.0.0/10, the range reserved for "+
				"carrier-grade NAT. Traffic is being translated at the ISP as well as at the "+
				"router, so an inbound connection cannot be made by forwarding a port however "+
				"the router is configured.", gw),
		).WithSummary(fmt.Sprintf(
			"Gateway %s is in the carrier-grade NAT range: inbound port forwarding cannot work.",
			gw,
		)).WithEvidence(
			model.Ev("default gateway", gw),
			model.Ev("range", "100.64.0.0/10"),
		).WithAdvice(
			"For inbound access use an outbound-initiated tunnel or a relay rather than port forwarding.",
		).WithPriority(55))
	}
	return out
}
