// Package ipv6 answers "is IPv6 actually usable here, or merely configured".
//
// Those are different questions and the gap between them is the whole point.
// A machine can hold a global IPv6 address and still have no working IPv6 path
// — stale prefix, a broken tunnel, a router that advertises but does not route.
// So this probe does not stop at enumerating addresses; it dials a real IPv6
// endpoint and reports whether the connection completes.
package ipv6

import (
	"bufio"
	"context"
	"io"
	"net"
	"strings"
	"time"

	"github.com/A015cc/why-slow/internal/model"
	"github.com/A015cc/why-slow/internal/netsys"
	"github.com/A015cc/why-slow/internal/probe"
)

// Compile-time proof that Probe satisfies the probe contract.
var _ probe.Probe = (*Probe)(nil)

const (
	probeName = "ipv6"
	// defaultTarget is a Cloudflare IPv6 resolver endpoint. If this is not
	// reachable, IPv6 is not usable in practice, whatever the interface table
	// claims.
	defaultTarget = "[2606:4700:4700::1111]:443"
	// dialTimeout keeps an unreachable IPv6 endpoint from dominating the run.
	dialTimeout = 4 * time.Second
)

// Probe measures IPv6 address inventory and reachability.
type Probe struct {
	env    *netsys.Env
	target string
}

// New builds an IPv6 probe. An empty target falls back to defaultTarget.
func New(env *netsys.Env, target string) *Probe {
	if strings.TrimSpace(target) == "" {
		target = defaultTarget
	}
	return &Probe{env: env, target: target}
}

// Name implements probe.Probe.
func (p *Probe) Name() string { return probeName }

// Run records the IPv6 observations.
func (p *Probe) Run(ctx context.Context, st *model.State) error {
	env := p.env
	if env == nil {
		env = netsys.DefaultEnv()
	}

	anyGlobal := false
	for _, ifc := range interfaces(env) {
		v6 := v6Of(ifc)
		if len(v6) == 0 {
			continue
		}
		n := countGlobal(v6)
		if n > 0 {
			anyGlobal = true
		}
		st.Add(
			model.Num(probeName, ifc.Name, "v6.global_count", "", float64(n), nil),
			model.Text(probeName, ifc.Name, "v6.classes", joinClasses(v6), nil),
		)
	}
	st.Add(model.Text(probeName, "ipv6", "ipv6.any_global", boolText(anyGlobal), nil))

	// Only recorded when a platform source exists; absence means unknown, not
	// "no route".
	if hasDefault, ok := defaultRouteV6(); ok {
		st.Add(model.Text(probeName, "ipv6", "ipv6.default_route", boolText(hasDefault), nil))
	}

	reachable, err := p.dialTest(ctx, env, p.target)
	md := map[string]string{"target": p.target}
	st.Add(model.Text(probeName, "ipv6", "ipv6.reachable", boolText(reachable), md))
	if err != nil {
		st.Add(model.Text(probeName, "ipv6", "ipv6.error", err.Error(), md))
	}
	return nil
}

// dialTest opens a TCP connection to the IPv6 endpoint. Success is the only
// portable proof that IPv6 carries traffic on this host.
func (p *Probe) dialTest(ctx context.Context, env *netsys.Env, target string) (bool, error) {
	dctx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()
	conn, err := dialFunc(env)(dctx, "tcp", target)
	if err != nil {
		return false, err
	}
	conn.Close()
	return true, nil
}

// interfaces enumerates interfaces, treating failure as an empty list.
func interfaces(env *netsys.Env) []netsys.Iface {
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

// v6Of returns an interface's IPv6 addresses, skipping IPv4 and nils.
func v6Of(ifc netsys.Iface) []net.IP {
	var out []net.IP
	for _, ip := range ifc.IPs() {
		if ip == nil || ip.To4() != nil {
			continue
		}
		out = append(out, ip)
	}
	return out
}

// countGlobal counts globally routable IPv6 addresses.
func countGlobal(ips []net.IP) int {
	n := 0
	for _, ip := range ips {
		if netsys.IsGlobalUnicastV6(ip) {
			n++
		}
	}
	return n
}

// joinClasses renders the role label of each address, comma-joined. The labels
// come from netsys.DescribeAddr so the report and the rules agree on wording.
func joinClasses(ips []net.IP) string {
	parts := make([]string, 0, len(ips))
	for _, ip := range ips {
		if ip == nil {
			continue
		}
		parts = append(parts, netsys.DescribeAddr(ip))
	}
	return strings.Join(parts, ", ")
}

// boolText encodes a boolean the way the rules read it.
func boolText(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// parseProcNetIPv6Route reads a Linux /proc/net/ipv6_route table and reports
// whether a default route is present. The second result is false when the table
// held no usable lines at all, which is distinct from "no default route".
//
// Like /proc/net/route this is a kernel interface rather than localized program
// output, so parsing it is safe — the opposite of scraping `ipconfig` on Chinese
// Windows. Columns: Destination(32 hex) Source(32) NextHop(32) Metric(8)
// RefCnt(8) Use(8) Flags(8) Iface. A default route is an all-zero destination
// with prefix length 0.
func parseProcNetIPv6Route(r io.Reader) (hasDefault, ok bool) {
	sc := bufio.NewScanner(r)
	sawLine := false
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 2 {
			continue
		}
		sawLine = true
		if len(fields[0]) == 32 && strings.Trim(fields[0], "0") == "" &&
			strings.Trim(fields[1], "0") == "" {
			return true, true
		}
	}
	return false, sawLine
}
