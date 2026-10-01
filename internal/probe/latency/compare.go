package latency

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"strings"
	"time"

	"github.com/A015cc/why-slow/internal/analyze"
	"github.com/A015cc/why-slow/internal/model"
	"github.com/A015cc/why-slow/internal/netsys"
	"github.com/A015cc/why-slow/internal/probe/path"
)

// compare measures two targets as interleaved pairs and reports the paired
// difference, rather than measuring one and then the other.
//
// The obvious approach — time A for a while, then time B — is the one that
// produces the wrong answer, and it produced it on the machine this tool was
// written on: a sequential test said UDP was three times faster than TCP, and an
// interleaved retest reversed the result. The link had drifted during the run,
// and the sequential design attributed that drift to the target.
//
// So each pair measures both targets back to back, and the order *within* the
// pair is decided by a coin flip. Without the coin flip the second measurement
// in every pair would systematically inherit the first one's hangover, which
// reintroduces exactly the ordering bias the pairing was meant to remove.
func (p *Probe) compare(ctx context.Context, st *model.State, env *netsys.Env, ipA net.IP, portA string, opts Options) error {
	hostB, portB := path.NormalizeTarget(opts.Compare)
	if hostB == "" {
		return errors.New("latency: empty compare target")
	}
	resB, err := resolveTarget(ctx, env, hostB, opts.Family)
	if err != nil {
		return err
	}
	picked := pickTargets(resB.ips, opts)
	if len(picked) == 0 {
		return errors.New("latency: no address for compare target " + opts.Compare)
	}
	ipB := picked[0]

	coin := opts.Coin
	if coin == nil {
		coin = func() bool { return rand.IntN(2) == 0 }
	}
	dial := dialFunc(env)

	deltas := make([]float64, 0, opts.Pairs)
	aFirst, skipped := 0, 0
	for i := 0; i < opts.Pairs; i++ {
		if i > 0 {
			if err := sleep(ctx, opts.Interval); err != nil {
				break
			}
		}
		firstIsA := coin()
		if firstIsA {
			aFirst++
		}
		sa, sb := measurePair(ctx, dial, ipA, portA, ipB, portB, opts.Timeout, firstIsA)

		// A pair with an incomplete side says nothing about the difference
		// between the targets, and a truncated sample would fabricate a delta of
		// roughly the whole timeout. Dropping the pair is the only honest move;
		// the count of dropped pairs is reported so the loss stays visible.
		if sa.outcome != outcomeOK || sb.outcome != outcomeOK {
			skipped++
			continue
		}
		deltas = append(deltas, sb.ms-sa.ms)
	}

	res := analyze.SignTest(deltas)
	subject := p.target + " vs " + opts.Compare
	md := map[string]string{
		"a":       p.target,
		"b":       opts.Compare,
		"ip_a":    ipA.String(),
		"ip_b":    ipB.String(),
		"a_first": fmt.Sprintf("%d/%d", aFirst, opts.Pairs),
	}

	obs := []model.Observation{
		model.Text(probeName, subject, KeyABLabelA, p.target, md),
		model.Text(probeName, subject, KeyABLabelB, opts.Compare, md),
		model.Text(probeName, subject, KeyABSummary, abSummary(res, skipped, opts.Pairs), md),
		model.Num(probeName, subject, KeyABPairs, "count", float64(res.N), md),
		model.Num(probeName, subject, KeyABSkipped, "count", float64(skipped), md),
		model.Num(probeName, subject, KeyABMedian, "ms", res.MedianDelta, md),
		model.Num(probeName, subject, KeyABPValue, "p", res.PValue, md),
		model.Num(probeName, subject, KeyABPositive, "count", float64(res.Positive), md),
		model.Num(probeName, subject, KeyABTies, "count", float64(res.Ties), md),
	}
	if len(deltas) > 0 {
		obs = append(obs, model.Series(probeName, subject, KeyABDelta, "ms", deltas, md))
	}
	st.Add(obs...)
	return nil
}

// measurePair measures one A/B pair, honouring the coin flip for the order
// inside the pair.
func measurePair(ctx context.Context, dial netsys.DialFunc, ipA net.IP, portA string, ipB net.IP, portB string, timeout time.Duration, firstIsA bool) (a, b sample) {
	if firstIsA {
		a = measure(ctx, dial, ipA, portA, timeout)
		b = measure(ctx, dial, ipB, portB, timeout)
		return a, b
	}
	b = measure(ctx, dial, ipB, portB, timeout)
	a = measure(ctx, dial, ipA, portA, timeout)
	return a, b
}

// abSummary renders the comparison as the sentence the report leads with.
//
// The p-value is stated rather than interpreted. A large p is the interesting
// outcome — it is the tool saying the difference a sequential test would have
// reported was drift — but the sentence leaves that reading to the rule engine,
// which is the layer allowed to draw conclusions.
func abSummary(r analyze.SignResult, skipped, requested int) string {
	var b strings.Builder
	fmt.Fprintf(&b, "median(B-A) = %+.1fms, sign test p = %.3f over %d pairs", r.MedianDelta, r.PValue, r.N)
	if r.Ties > 0 {
		fmt.Fprintf(&b, " (%d tied)", r.Ties)
	}
	if skipped > 0 {
		fmt.Fprintf(&b, "; %d of %d pairs dropped as incomplete", skipped, requested)
	}
	return b.String()
}
