// Command why-slow diagnoses why a network path is slow.
//
// It differs from a TCP ping in what it reports. A ping tells you how slow a
// path is; this tells you what is making it slow, with the evidence attached and
// a confidence level — and it says "the shape matches, but here are the other
// things that produce the same shape" when that is the honest answer.
//
// The binary is deliberately tiny: it wires up the CLI and gets out of the way.
// Everything with a decision in it lives in internal/, where it can be tested
// without a network.
package main

import (
	"os"

	"github.com/A015cc/why-slow/internal/cli"
)

// Injected by goreleaser at link time (-ldflags -X main.version=...). The defaults
// are what a `go build` from a working tree reports.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	os.Exit(cli.Main(os.Args, cli.BuildInfo{Version: version, Commit: commit, Date: date}))
}
