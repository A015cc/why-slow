// Package path answers "how does traffic to this target actually leave the
// machine". It records the egress interface and source address, the host's
// default gateway, and a snapshot of every interface — the facts a rule needs to
// say "your latency is being measured through a TUN, not the physical link".
//
// Everything here is best-effort and read-only. Where a platform does not expose
// a fact portably, the probe records nothing rather than a guess: a confidently
// wrong gateway would poison every downstream conclusion, while a missing one
// merely narrows what the report can say.
package path

import (
	"context"
	"errors"
	"net"
	"time"

	"github.com/A015cc/why-slow/internal/model"
	"github.com/A015cc/why-slow/internal/netsys"
	"github.com/A015cc/why-slow/internal/probe"
)

const probeName = "path"

// Compile-time proof that Probe satisfies the probe contract.
var _ probe.Probe = (*Probe)(nil)

// Probe measures the egress path toward a single target.
type Probe struct {
	env    *netsys.Env
	target string
}

// New builds a path probe for target, which may be a hostname, an IP literal, or
// either with a ":port" suffix.
func New(env *netsys.Env, target string) *Probe {
	return &Probe{env: env, target: target}
}

// Name implements probe.Probe.
func (p *Probe) Name() string { return probeName }

// Run records the path observations. Interface and gateway facts are recorded
// even if the egress lookup later fails, so a partial diagnosis is still
// available to the rules.
func (p *Probe) Run(ctx context.Context, st *model.State) error {
	env := p.env
	if env == nil {
		env = netsys.DefaultEnv()
	}
	ifaces := p.interfaces(env)

	p.observeIfaces(st, ifaces)
	p.observeGateway(st)

	host, port := normalizeTarget(p.target)
	subject := host
	if subject == "" {
		subject = "target"
	}

	remoteIP, err := p.resolve(ctx, env, host)
	if err != nil {
		return err
	}
	src, err := egressSource(ctx, dialFunc(env), remoteIP, port)
	if err != nil {
		return err
	}

	md := map[string]string{"remote_ip": remoteIP.String()}
	st.Add(model.Text(probeName, subject, "egress.src_ip", src.String(), md))
	if ifc, ok := netsys.ByIP(ifaces, src); ok {
		st.Add(
			model.Text(probeName, subject, "egress.iface", ifc.Name, md),
			model.Text(probeName, subject, "egress.is_virtual", boolText(ifc.Virtual), md),
			model.Text(probeName, subject, "egress.kind", kindOf(ifc.Virtual, ifc.Kind), md),
			model.Num(probeName, subject, "egress.index", "", float64(ifc.Index), md),
		)
		return nil
	}
	// Source address known but no interface claims it (a transient virtual
	// adapter, for example). Record the address; say nothing false about the
	// interface.
	st.Add(model.Text(probeName, subject, "egress.iface", "unknown", md))
	return nil
}

// observeIfaces records the per-interface inventory under each interface name.
func (p *Probe) observeIfaces(st *model.State, ifaces []netsys.Iface) {
	for _, ifc := range ifaces {
		st.Add(
			model.Text(probeName, ifc.Name, "iface.virtual", boolText(ifc.Virtual), nil),
			model.Text(probeName, ifc.Name, "iface.kind", kindOf(ifc.Virtual, ifc.Kind), nil),
			model.Text(probeName, ifc.Name, "iface.up", boolText(ifc.Up), nil),
			model.Text(probeName, ifc.Name, "iface.addrs", joinAddrs(ifc.Addrs), nil),
		)
	}
}

// observeGateway records the default gateway when — and only when — it is
// actually known. On platforms where it cannot be read portably the observations
// are simply absent, which the rules must treat as "unknown". See
// DefaultGateway for why that is the deliberate choice.
func (p *Probe) observeGateway(st *model.State) {
	gw, ok := DefaultGateway()
	if !ok || gw == nil {
		return
	}
	st.Add(
		model.Text(probeName, subjectDefault, "gateway", gw.String(), nil),
		model.Text(probeName, subjectDefault, "gateway.is_cgnat", boolText(netsys.IsCGNAT(gw)), nil),
	)
}

// resolve turns the target into a concrete IP, preferring IPv4 because that is
// the family most failures are about and the egress interface can differ by
// family.
func (p *Probe) resolve(ctx context.Context, env *netsys.Env, host string) (net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		return ip, nil
	}
	if host == "" {
		return nil, errors.New("path: empty target")
	}
	res := env.Resolver
	if res == nil {
		res = net.DefaultResolver
	}
	addrs, err := res.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	if len(addrs) == 0 {
		return nil, errors.New("path: no addresses for " + host)
	}
	for _, a := range addrs {
		if a.IP.To4() != nil {
			return a.IP, nil
		}
	}
	return addrs[0].IP, nil
}

// interfaces enumerates interfaces, treating failure as an empty list: the probe
// is still useful without the inventory.
func (p *Probe) interfaces(env *netsys.Env) []netsys.Iface {
	if env != nil && env.Ifaces != nil {
		if list, err := env.Ifaces(); err == nil {
			return list
		}
	}
	return nil
}

// dialFunc returns the Env's dialer, falling back to a plain one so a zero Env
// still works.
func dialFunc(env *netsys.Env) netsys.DialFunc {
	if env != nil && env.Dial != nil {
		return env.Dial
	}
	d := &net.Dialer{Timeout: 5 * time.Second}
	return d.DialContext
}
