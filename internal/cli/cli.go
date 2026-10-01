// Package cli is the command-line surface.
//
// Subcommands are declared as data rather than as a package each. There are five
// of them, between them they take six flags, and all the shared work lives in
// run.go — so a command framework would add a dependency and a layer of
// indirection to buy nothing at this size.
//
// The package is disciplined about one thing in particular: it decides *nothing*
// about the measurements. It wires probes together, hands the resulting
// observations to the verdict engine, and hands the findings to a renderer.
// Every conclusion in the output was drawn by a pure rule, which is what makes
// those conclusions testable without a network.
package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"github.com/A015cc/why-slow/internal/netsys"
	"github.com/A015cc/why-slow/internal/probe"
	"github.com/A015cc/why-slow/internal/probe/ipv6"
	"github.com/A015cc/why-slow/internal/probe/latency"
	"github.com/A015cc/why-slow/internal/probe/nat"
	"github.com/A015cc/why-slow/internal/probe/path"
)

// BuildInfo carries the values goreleaser injects at link time.
type BuildInfo struct {
	Version string
	Commit  string
	Date    string
}

const (
	exitOK     = 0
	exitFailed = 1
	exitUsage  = 2
)

// config holds every flag value, shared and per-command.
type config struct {
	prog   string
	target string

	n        int
	timeout  time.Duration
	interval time.Duration
	family   string
	ab       string

	json    bool
	noColor bool
}

// httpTimeout is the bound for the HTTP-based public-address lookups.
//
// --timeout is documented as bounding a dial, and 5s is the right default for a
// single TCP handshake. It is the wrong bound for "fetch a small document over
// TLS from a possibly distant endpoint", so the HTTP budget is the larger of the
// two rather than the same number.
func (c config) httpTimeout() time.Duration {
	if c.timeout > 10*time.Second {
		return c.timeout
	}
	return 10 * time.Second
}

// command is one subcommand.
type command struct {
	name    string
	summary string
	// needsTarget marks commands whose positional target is not optional.
	needsTarget bool
	flags       func(fs *flag.FlagSet, cfg *config)
	probes      func(cfg config) (probeSet, error)
}

// commands is the command table, in the order the help text lists them.
var commands = []command{
	{
		name:    "all",
		summary: "run every probe against one target",
		flags:   latencyFlags,
		probes: func(cfg config) (probeSet, error) {
			env := environment(cfg)
			var set probeSet
			if cfg.target != "" {
				set.primary = append(set.primary, latencyProbe(env, cfg))
				set.parallel = append(set.parallel, path.New(env, cfg.target))
			}
			// nat and ipv6 are about the host, so they are useful with or without
			// a target and always run.
			set.parallel = append(set.parallel, nat.New(env), ipv6.New(env, ""))
			return set, nil
		},
	},
	{
		name:        "latency",
		summary:     "handshake timing, then ladder / loss analysis",
		needsTarget: true,
		flags:       latencyFlags,
		probes: func(cfg config) (probeSet, error) {
			if err := requireTarget(cfg, "latency"); err != nil {
				return probeSet{}, err
			}
			return probeSet{primary: []probe.Probe{latencyProbe(environment(cfg), cfg)}}, nil
		},
	},
	{
		name:        "path",
		summary:     "interface, route and egress attribution",
		needsTarget: true,
		flags:       nil,
		probes: func(cfg config) (probeSet, error) {
			if err := requireTarget(cfg, "path"); err != nil {
				return probeSet{}, err
			}
			return probeSet{parallel: []probe.Probe{path.New(environment(cfg), cfg.target)}}, nil
		},
	},
	{
		name:    "nat",
		summary: "local / gateway / public address comparison",
		probes: func(cfg config) (probeSet, error) {
			return probeSet{parallel: []probe.Probe{nat.New(environment(cfg))}}, nil
		},
	},
	{
		name:    "ipv6",
		summary: "IPv6 address, route and reachability check",
		probes: func(cfg config) (probeSet, error) {
			// The target is optional here: empty means the probe's own default
			// endpoint, which is a dual-stack service chosen to be reachable.
			return probeSet{parallel: []probe.Probe{ipv6.New(environment(cfg), cfg.target)}}, nil
		},
	},
}

func lookupCommand(name string) (command, bool) {
	for _, c := range commands {
		if c.name == name {
			return c, true
		}
	}
	return command{}, false
}

// latencyProbe builds the flagship probe from the parsed flags.
func latencyProbe(env *netsys.Env, cfg config) probe.Probe {
	return latency.New(env, cfg.target, latency.Options{
		N:        cfg.n,
		Timeout:  cfg.timeout,
		Interval: cfg.interval,
		Family:   cfg.family,
		Compare:  cfg.ab,
	})
}

// environment builds the OS-facing dependencies the probes share.
func environment(cfg config) *netsys.Env {
	env := netsys.DefaultEnv()
	env.Dial = (&net.Dialer{Timeout: cfg.timeout}).DialContext
	env.HTTP = netsys.DirectClient(cfg.httpTimeout())
	env.PublicIPTimeout = cfg.httpTimeout()
	return env
}

func requireTarget(cfg config, name string) error {
	if cfg.target == "" {
		return fmt.Errorf("%s needs a target, e.g. `why-slow %s example.net:443`", name, name)
	}
	return nil
}

// Main runs the command line and returns the process exit code.
func Main(args []string, build BuildInfo) int {
	prog := "why-slow"
	rest := args
	if len(args) > 0 {
		prog = args[0]
		rest = args[1:]
	}

	if len(rest) > 0 {
		switch rest[0] {
		case "-h", "-help", "--help", "help":
			usage(os.Stdout, prog)
			return exitOK
		case "-v", "-version", "--version", "version":
			fmt.Fprintf(os.Stdout, "%s %s (commit %s, built %s)\n",
				prog, orDefault(build.Version, "dev"), orDefault(build.Commit, "none"), orDefault(build.Date, "unknown"))
			return exitOK
		}
	}

	// The bare invocation runs the probes that need no target, so `why-slow` and
	// `why-slow --json` both work without a command word.
	name := "all"
	var cmdArgs []string
	if len(rest) > 0 && !strings.HasPrefix(rest[0], "-") {
		name = rest[0]
		cmdArgs = rest[1:]
	} else {
		cmdArgs = rest
	}

	cmd, ok := lookupCommand(name)
	if !ok {
		fmt.Fprintf(os.Stderr, "%s: unknown command %q\n\n", prog, name)
		usage(os.Stderr, prog)
		return exitUsage
	}

	cfg := config{prog: prog, n: 40, timeout: 5 * time.Second, interval: 200 * time.Millisecond, family: "auto"}
	fs := flag.NewFlagSet(prog+" "+name, flag.ContinueOnError)
	// Errors are reported by this package so they can be followed by the usage
	// text; the FlagSet's own chatter would duplicate both.
	fs.SetOutput(io.Discard)
	registerGlobalFlags(fs, &cfg)
	if cmd.flags != nil {
		cmd.flags(fs, &cfg)
	}
	if err := fs.Parse(cmdArgs); err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n\n", prog, err)
		usage(os.Stderr, prog)
		return exitUsage
	}
	cfg.target = strings.TrimSpace(fs.Arg(0))

	if err := validate(cfg, cmd); err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n\n", prog, err)
		usage(os.Stderr, prog)
		return exitUsage
	}

	return execute(cmd, cfg, build, os.Stdout)
}

// validate rejects bad flag combinations up front. Failing before any probe runs
// matters for the latency command in particular: a typo in --family would
// otherwise be discovered after several minutes of measurement.
func validate(cfg config, cmd command) error {
	switch cfg.family {
	case "4", "6", "auto":
	default:
		return fmt.Errorf("--family must be 4, 6 or auto, not %q", cfg.family)
	}
	if cfg.n <= 0 {
		return errors.New("-n must be at least 1")
	}
	if cfg.timeout <= 0 {
		return errors.New("--timeout must be positive")
	}
	if cmd.needsTarget && cfg.target == "" {
		return requireTarget(cfg, cmd.name)
	}
	return nil
}

func registerGlobalFlags(fs *flag.FlagSet, cfg *config) {
	fs.BoolVar(&cfg.json, "json", false, "machine-readable output carrying a versioned schema_version")
	fs.BoolVar(&cfg.noColor, "no-color", false, "disable ANSI colour (also off when the output is not a terminal)")
	fs.DurationVar(&cfg.timeout, "timeout", cfg.timeout, "bound on each dial")
	fs.StringVar(&cfg.family, "family", cfg.family, "restrict address selection to 4 or 6")
}

func latencyFlags(fs *flag.FlagSet, cfg *config) {
	fs.IntVar(&cfg.n, "n", cfg.n, "handshake samples to take")
	fs.StringVar(&cfg.ab, "ab", "", "second target to compare against, measured interleaved")
}

func usage(w io.Writer, prog string) {
	fmt.Fprintf(w, `%[1]s diagnoses why a network path is slow: it reports conclusions
with their evidence and a confidence level, not just measurements.

Usage:
  %[1]s [flags]                     probes that need no target
  %[1]s all <host:port>             every probe against one target
  %[1]s latency <host:port>         handshake timing, then ladder / loss analysis
  %[1]s path <host>                 interface, route and egress attribution
  %[1]s nat                         local / gateway / public address comparison
  %[1]s ipv6 [target]               IPv6 address, route and reachability check

Flags:
  --json               machine-readable output carrying a versioned schema_version
  --no-color           disable ANSI colour (also off when output is not a terminal)
  --timeout duration   bound on each dial (default 5s)
  --family 4|6|auto    restrict address selection (default auto; prefers IPv4)

latency only:
  -n int               handshake samples to take (default 40)
  --ab <host:port>     second target, measured interleaved with a paired sign test

  --version            print version and exit
  -h, --help           print this help

Exit status:
  0  the run completed. Findings do not change this: a diagnosis that found
     something wrong did its job.
  1  every probe failed, so the report carries no measurement.
  2  usage error.
`, prog)
}

func orDefault(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}
