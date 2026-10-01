package cli

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/A015cc/why-slow/internal/model"
	"github.com/A015cc/why-slow/internal/probe"
	"github.com/A015cc/why-slow/internal/render"
	"github.com/A015cc/why-slow/internal/verdict"
)

// probeSet is a command's probes, split by how they must be scheduled.
type probeSet struct {
	// primary runs first and alone. The latency measurement lives here because
	// concurrent connects inflate RTT and can trip a middlebox's or server's SYN
	// flood protection — which would manufacture the very bimodality the tool
	// exists to find. Nothing else may run while this does.
	primary []probe.Probe
	// parallel runs afterwards, concurrently. These probes are independent and
	// I/O bound, and by then they no longer contend with a sensitive measurement.
	parallel []probe.Probe
}

// execute runs the probes and writes the report.
func execute(cmd command, cfg config, build BuildInfo, out *os.File) int {
	started := time.Now()
	ctx := context.Background()

	set, err := cmd.probes(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", cfg.prog, err)
		return exitUsage
	}

	st := model.NewState()
	var probeErrors []model.ProbeError
	total := len(set.primary) + len(set.parallel)

	for _, p := range set.primary {
		name, err := runOne(ctx, p, st, cfg)
		if err != nil {
			probeErrors = append(probeErrors, model.ProbeError{Probe: name, Err: err.Error()})
		}
	}

	// Each concurrent probe records into its own State and the results are merged
	// under a lock. Sharing one State would be a data race on its index maps;
	// locking around the probe call instead would serialise the measurements,
	// which is the one thing the phasing exists to avoid.
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, p := range set.parallel {
		wg.Add(1)
		go func(p probe.Probe) {
			defer wg.Done()
			sub := model.NewState()
			name, err := runOne(ctx, p, sub, cfg)
			mu.Lock()
			defer mu.Unlock()
			st.Add(sub.All()...)
			if err != nil {
				probeErrors = append(probeErrors, model.ProbeError{Probe: name, Err: err.Error()})
			}
		}(p)
	}
	wg.Wait()

	findings := verdict.Run(st)
	rep := &model.Report{
		SchemaVersion: model.SchemaVersion,
		Tool:          "why-slow",
		Version:       orDefault(build.Version, "dev"),
		StartedAt:     started,
		DurationMS:    float64(time.Since(started)) / float64(time.Millisecond),
		Target:        cfg.target,
		Observations:  st.All(),
		Findings:      findings,
		Verdict:       verdict.Verdict(findings),
		ProbeErrors:   probeErrors,
	}

	if cfg.json {
		if err := render.JSON(out, rep); err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", cfg.prog, err)
			return exitFailed
		}
	} else {
		opts := render.Options{Color: !cfg.noColor && render.ColorEnabled(out)}
		if err := render.Human(out, rep, opts); err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", cfg.prog, err)
			return exitFailed
		}
	}

	if total > 0 && len(probeErrors) >= total {
		return exitFailed
	}
	return exitOK
}

// runOne runs a single probe under its own deadline and panic barrier.
//
// Both guards exist for the same reason: a report that is missing one probe's
// contribution is far more useful than no report. A panic in an unfamiliar
// syscall or a nil map must cost its own probe and nothing else, and the
// observations it managed to record before dying are kept.
func runOne(ctx context.Context, p probe.Probe, st *model.State, cfg config) (name string, err error) {
	name = p.Name()
	pctx, cancel := context.WithTimeout(ctx, budgetFor(name, cfg))
	defer cancel()

	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic: %v", r)
		}
	}()
	return name, p.Run(pctx, st)
}

// budgetFor bounds a single probe.
//
// The latency probe's worst case is not a constant: every sample may burn the
// whole dial timeout, so the budget has to be derived from the sample count.
// Using a fixed number here would either kill a legitimately slow run midway or
// leave a hung one running indefinitely — and the failure would only show up on
// exactly the lossy paths the tool is for.
func budgetFor(name string, cfg config) time.Duration {
	if name != "latency" {
		return 30 * time.Second
	}
	// One interval per sample, plus the dial itself, plus a margin for the DNS
	// lookup and report assembly.
	worst := time.Duration(cfg.n+1) * (cfg.timeout + cfg.interval)
	if cfg.ab != "" {
		// An A/B run measures two targets per pair.
		worst *= 2
	}
	return worst + 30*time.Second
}
