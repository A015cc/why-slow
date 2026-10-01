// Package nat answers "what does the internet think my address is, and is there
// a carrier-grade NAT in the way".
//
// The public-IP lookup is the whole reason this probe exists, and it is
// deliberately routed through a proxy-bypassing HTTP client: on a machine whose
// system proxy forwards to a VPS, the address an ordinary request sees is the
// VPS's, and a diagnosis built on it would report a datacenter as the user's
// ISP. The test suite pins that behaviour down.
package nat

import (
	"context"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/A015cc/why-slow/internal/model"
	"github.com/A015cc/why-slow/internal/netsys"
	"github.com/A015cc/why-slow/internal/probe"
	"github.com/A015cc/why-slow/internal/probe/path"
)

const probeName = "nat"

// Compile-time proof that Probe satisfies the probe contract.
var _ probe.Probe = (*Probe)(nil)

// Probe measures the public address, the STUN-observed mapping, and whether the
// evidence supports a carrier-grade NAT conclusion.
type Probe struct {
	env *netsys.Env
}

// New builds a nat probe. It needs no target: the subject is the host itself.
func New(env *netsys.Env) *Probe { return &Probe{env: env} }

// Name implements probe.Probe.
func (p *Probe) Name() string { return probeName }

// Run records all nat observations. Nothing here is fatal: each sub-measurement
// degrades to an error observation while the others still report.
func (p *Probe) Run(ctx context.Context, st *model.State) error {
	env := p.env
	if env == nil {
		env = netsys.DefaultEnv()
	}
	pub := p.lookupPublic(ctx)
	p.emitPublic(st, pub)

	stunRes := p.lookupSTUN(ctx, env)
	p.emitSTUN(st, stunRes)

	p.emitConclusion(env, st, pub)
	return nil
}

// emitConclusion records nat.cgnat and nat.reason.
//
// The honest position: from the host we can see our own addresses and the
// gateway, but not the router's WAN address, so "home NAT" and "carrier NAT"
// are not directly distinguishable. CGNAT is claimed true only on concrete
// evidence, and "false" only when the public address is one we hold locally
// (which means there is no NAT at all). Everything else is "unknown" with a
// reason that says exactly what was observable, because overclaiming here sends
// users to the wrong fix — port forwarding cannot help behind carrier NAT.
func (p *Probe) emitConclusion(env *netsys.Env, st *model.State, pub publicResult) {
	const subj = "nat"
	ifaces := p.interfaces(env)

	var cgnatLocal []string
	var virtualCGNAT []string
	var localPublic []net.IP
	for _, ifc := range ifaces {
		for _, ip := range ifc.IPs() {
			if netsys.IsCGNAT(ip) {
				// An address in 100.64.0.0/10 is only evidence of carrier NAT when
				// it sits on real hardware. Overlay networks assign themselves
				// addresses out of the same range on purpose — Tailscale does, so
				// that its traffic stays unroutable on the public internet — and an
				// address alone cannot tell the two apart. Counting it would report
				// the user's own VPN as their ISP's NAT, and then advise them to
				// work around it with the VPN they are already running. Recorded so
				// the reasoning stays visible, deliberately not counted.
				if ifc.Virtual {
					virtualCGNAT = append(virtualCGNAT, ip.String()+" on "+ifc.Name)
					continue
				}
				cgnatLocal = append(cgnatLocal, ip.String())
				continue
			}
			if v4 := ip.To4(); v4 != nil &&
				!netsys.IsPrivate(v4) && !netsys.IsLoopback(v4) && !netsys.IsLinkLocal(v4) {
				localPublic = append(localPublic, v4)
			}
		}
	}

	gw, gwKnown := path.DefaultGateway()

	value := "unknown"
	var evidence []string

	if len(cgnatLocal) > 0 {
		value = "true"
		evidence = append(evidence, "local address in 100.64.0.0/10: "+strings.Join(cgnatLocal, ","))
	}
	if pub.v4 != nil && netsys.IsCGNAT(pub.v4) {
		value = "true"
		evidence = append(evidence, "public IPv4 "+pub.v4.String()+" is in 100.64.0.0/10")
	}
	if gwKnown && gw != nil && netsys.IsCGNAT(gw) {
		value = "true"
		evidence = append(evidence, "default gateway "+gw.String()+" is in 100.64.0.0/10")
	}

	if value == "unknown" && pub.v4 != nil {
		for _, ip := range localPublic {
			if ip.Equal(pub.v4) {
				value = "false"
				evidence = append(evidence, "public IPv4 equals local interface address "+ip.String()+": no NAT in the path")
				break
			}
		}
	}

	var reason string
	switch {
	case len(evidence) > 0:
		reason = strings.Join(evidence, "; ")
	default:
		reason = "own addresses are not in 100.64.0.0/10 and the public address is not one held locally"
		if !gwKnown {
			reason += "; the default gateway could not be read on this platform"
		} else if gw != nil {
			reason += "; default gateway " + gw.String() + " is not in 100.64.0.0/10"
		}
		reason += "; a router one hop away may still be doing carrier NAT, which this host cannot see"
	}
	if len(virtualCGNAT) > 0 {
		reason += "; ignored " + strings.Join(virtualCGNAT, ", ") +
			" because the adapter is a tunnel, which assigns addresses from that range itself"
	}

	st.Add(
		model.Text(probeName, subj, "nat.cgnat", value, nil),
		model.Text(probeName, subj, "nat.reason", reason, nil),
	)
}

// client returns the HTTP client for the public-IP lookups. Env.HTTP is a
// netsys.DirectClient under DefaultEnv. When an Env supplies none we still
// refuse to fall back to http.DefaultClient, because that client honours
// HTTP_PROXY and would silently reintroduce the exact bug this probe guards
// against; netsys.DirectClient is the safe default.
func (p *Probe) client() *http.Client {
	if p.env != nil && p.env.HTTP != nil {
		return p.env.HTTP
	}
	return netsys.DirectClient(10 * time.Second)
}

func (p *Probe) interfaces(env *netsys.Env) []netsys.Iface {
	if env != nil && env.Ifaces != nil {
		if list, err := env.Ifaces(); err == nil {
			return list
		}
	}
	return nil
}

// dialFunc returns the Env's dialer, falling back to a plain one.
func dialFunc(env *netsys.Env) netsys.DialFunc {
	if env != nil && env.Dial != nil {
		return env.Dial
	}
	d := &net.Dialer{Timeout: 5 * time.Second}
	return d.DialContext
}

// boolText encodes a boolean the way the rules read it.
func boolText(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
