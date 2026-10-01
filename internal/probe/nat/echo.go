package nat

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/A015cc/why-slow/internal/model"
)

// maxEchoBody caps how much of a provider response is read. An IP echo is a few
// dozen bytes; anything larger is not an answer worth trusting.
const maxEchoBody = 4096

// endpoint is one public-IP echo service.
type endpoint struct {
	provider string
	url      string
	parse    func([]byte) string
}

// v4Endpoints are queried independently of each other purely so their answers
// can be cross-checked: a single provider returning a datacenter address is the
// exact failure this tool exists to catch.
var v4Endpoints = []endpoint{
	{"cloudflare", "https://1.1.1.1/cdn-cgi/trace", parseCloudflareTrace},
	{"ipify", "https://api.ipify.org", parsePlainBody},
	{"icanhazip", "https://ipv4.icanhazip.com", parsePlainBody},
}

// v6Endpoints are only reachable when the host actually has working IPv6; a
// failure here is expected on many networks and is never fatal.
var v6Endpoints = []endpoint{
	{"cloudflare", "https://[2606:4700:4700::1111]/cdn-cgi/trace", parseCloudflareTrace},
	{"icanhazip", "https://ipv6.icanhazip.com", parsePlainBody},
}

// publicResult is the outcome of the public-IP lookups.
type publicResult struct {
	v4       net.IP
	v6       net.IP
	provider string // provider(s) that answered for IPv4
	// answers is how many IPv4 providers replied. It is recorded separately from
	// agreement because the two answer different questions, and a reader that
	// conflates them will accuse the network of interception on the strength of a
	// single measurement: agreement is false both when two providers differ and
	// when only one replied, and only the count distinguishes those cases.
	answers   int
	agreement bool  // two or more IPv4 providers answered and all agreed
	err       error // set only when no IPv4 provider answered at all
}

// lookupPublic queries the IPv4 and IPv6 echo endpoints. It uses the Env's HTTP
// client, which is a proxy-bypassing one, so the address reported is the host's
// own and not the proxy's.
func (p *Probe) lookupPublic(ctx context.Context) publicResult {
	c := p.client()
	var res publicResult

	var v4s []net.IP
	var providers []string
	var failed []string
	for _, ep := range v4Endpoints {
		ip, err := fetchIP(ctx, c, ep)
		if err != nil {
			failed = append(failed, ep.provider)
			continue
		}
		v4s = append(v4s, ip)
		providers = append(providers, ep.provider)
	}
	if len(v4s) > 0 {
		res.v4 = v4s[0]
		res.answers = len(v4s)
		res.provider = strings.Join(providers, "+")
		// Agreement is only meaningful with at least two answers. A lone answer
		// cannot agree with anything, so it is recorded as disagreement rather
		// than as a silent pass — and res.answers is what lets a reader tell that
		// case apart from two providers genuinely returning different addresses.
		res.agreement = len(v4s) >= 2
		for _, ip := range v4s[1:] {
			if !ip.Equal(v4s[0]) {
				res.agreement = false
			}
		}
	} else {
		res.err = errors.New("nat: no IPv4 public-IP provider answered (" + strings.Join(failed, ",") + ")")
	}

	for _, ep := range v6Endpoints {
		ip, err := fetchIP(ctx, c, ep)
		if err != nil {
			continue
		}
		if ip.To4() == nil {
			res.v6 = ip
			break
		}
	}
	return res
}

// emitPublic records the public-IP observations under subject "public".
func (p *Probe) emitPublic(st *model.State, r publicResult) {
	const subj = "public"
	var obs []model.Observation
	if r.v4 != nil {
		obs = append(obs, model.Text(probeName, subj, "public.ip.v4", r.v4.String(), nil))
	}
	if r.v6 != nil {
		obs = append(obs, model.Text(probeName, subj, "public.ip.v6", r.v6.String(), nil))
	}
	if r.provider != "" {
		obs = append(obs, model.Text(probeName, subj, "public.provider", r.provider, nil))
	}
	obs = append(obs,
		model.Num(probeName, subj, "public.answers_n", "count", float64(r.answers), nil),
		model.Text(probeName, subj, "public.agreement", boolText(r.agreement), nil),
	)
	if r.err != nil {
		obs = append(obs, model.Text(probeName, subj, "public.error", r.err.Error(), nil))
	}
	st.Add(obs...)
}

// fetchIP performs one echo request and parses out the address.
func fetchIP(ctx context.Context, c *http.Client, ep endpoint) (net.IP, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ep.url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("nat: " + ep.provider + ": HTTP " + strconv.Itoa(resp.StatusCode))
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxEchoBody))
	if err != nil {
		return nil, err
	}
	raw := strings.TrimSpace(ep.parse(body))
	if raw == "" {
		return nil, errors.New("nat: " + ep.provider + ": no address in response")
	}
	ip := net.ParseIP(raw)
	if ip == nil {
		return nil, errors.New("nat: " + ep.provider + ": unparseable address " + strconv.Quote(raw))
	}
	return ip, nil
}

// parseCloudflareTrace pulls the value of the "ip=" line out of Cloudflare's
// cdn-cgi/trace output, which is a flat key=value document.
func parseCloudflareTrace(b []byte) string {
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if v, ok := strings.CutPrefix(line, "ip="); ok {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// parsePlainBody returns the first whitespace-delimited token that parses as an
// IP. Several providers append a trailing newline, and some echo a banner first.
func parsePlainBody(b []byte) string {
	for _, tok := range strings.Fields(string(b)) {
		if net.ParseIP(tok) != nil {
			return tok
		}
	}
	return ""
}
