package latency

import (
	"context"
	"net"
	"strings"
	"time"

	"github.com/A015cc/why-slow/internal/netsys"
)

// resolution is the result of turning a target into addresses.
type resolution struct {
	ips []net.IP
	ms  float64
	// didLookup is false for an IP literal, where there was no lookup to time.
	// The distinction matters because an absent dns.lookup_ms means "not
	// applicable", not "instant".
	didLookup bool
}

// resolveTarget resolves host, timing the lookup separately from the handshake.
//
// An IP literal short-circuits: it is accepted as-is and no lookup is recorded,
// so a report never shows a DNS time for a target that never touched a resolver.
// Family filtering happens here rather than at dial time so that a target with
// only AAAA records and --family 4 fails loudly instead of dialling something
// the user did not ask for.
func resolveTarget(ctx context.Context, env *netsys.Env, host, family string) (resolution, error) {
	if ip := net.ParseIP(host); ip != nil {
		ips := filterFamily([]net.IP{ip}, family)
		if len(ips) == 0 {
			return resolution{}, &FamilyError{Host: host, Family: family}
		}
		return resolution{ips: ips}, nil
	}

	res := net.DefaultResolver
	if env != nil && env.Resolver != nil {
		res = env.Resolver
	}

	start := time.Now()
	addrs, err := res.LookupIPAddr(ctx, host)
	elapsed := time.Since(start)
	if err != nil {
		return resolution{}, err
	}

	ips := make([]net.IP, 0, len(addrs))
	for _, a := range addrs {
		if a.IP != nil {
			ips = append(ips, a.IP)
		}
	}
	out := resolution{ips: filterFamily(ips, family), ms: millis(elapsed), didLookup: true}
	if len(out.ips) == 0 {
		return out, &FamilyError{Host: host, Family: family}
	}
	return out, nil
}

// FamilyError reports that a name resolved, but not in the requested family.
type FamilyError struct {
	Host   string
	Family string
}

func (e *FamilyError) Error() string {
	if e.Family == "" || e.Family == "auto" {
		return "no address for " + e.Host
	}
	return "no IPv" + e.Family + " address for " + e.Host
}

// formatIPs renders addresses for observation metadata.
func formatIPs(ips []net.IP) string {
	parts := make([]string, 0, len(ips))
	for _, ip := range ips {
		if ip == nil {
			continue
		}
		parts = append(parts, ip.String())
	}
	return strings.Join(parts, ",")
}

// filterFamily keeps only addresses of the requested family. "auto" keeps both,
// and the preference between them is applied later by pickTargets.
func filterFamily(ips []net.IP, family string) []net.IP {
	switch family {
	case "4":
		return keep(ips, func(ip net.IP) bool { return ip.To4() != nil })
	case "6":
		return keep(ips, func(ip net.IP) bool { return ip.To4() == nil })
	default:
		return ips
	}
}

func keep(ips []net.IP, pred func(net.IP) bool) []net.IP {
	var out []net.IP
	for _, ip := range ips {
		if pred(ip) {
			out = append(out, ip)
		}
	}
	return out
}

// pickTargets decides which addresses to actually measure.
//
// IPv4 wins the default case. The failures this tool was written for are IPv4
// failures — a path that eats SYNs, a carrier NAT in front of the host, a long-haul link
// that retransmits — while on a dual-stack host IPv6 frequently takes an
// entirely different (and often cleaner) route. Measuring the v6 address by
// default would hand back a healthy number for a v4 problem, which is worse than
// reporting nothing. --family 6 or --all-ips are the explicit opt-ins.
//
// resolveTarget has already filtered the list by family, so in the normal path
// only one kind is present and this is just "take the first". The preference is
// still applied here because a mixed list must not silently degrade a --family 6
// request into an IPv4 measurement.
func pickTargets(ips []net.IP, opts Options) []net.IP {
	if len(ips) == 0 {
		return nil
	}
	if opts.AllIPs {
		return ips
	}
	want4 := opts.Family != "6"
	for _, ip := range ips {
		if (ip.To4() != nil) == want4 {
			return []net.IP{ip}
		}
	}
	// Nothing of the preferred family. An "auto" request for a v6-only name is
	// the case that lands here, and measuring it beats measuring nothing.
	return []net.IP{ips[0]}
}
