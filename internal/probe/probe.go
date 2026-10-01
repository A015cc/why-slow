// Package probe defines the collection half of the pipeline.
//
// A probe measures and records. It does not interpret. Interpretation belongs
// to the verdict engine, because the strongest conclusions draw on evidence
// from several probes at once — "the latency samples show a retransmission
// ladder AND the path probe shows egress through a TUN, so the numbers may
// describe the tunnel rather than the link" is not a statement any single probe
// is in a position to make.
package probe

import (
	"context"

	"github.com/A015cc/why-slow/internal/model"
)

// Probe is a unit of measurement.
type Probe interface {
	// Name is the stable identifier recorded as Observation.Probe.
	Name() string
	// Run records observations into st. Returning an error is acceptable and
	// expected: callers keep whatever was already recorded and report the
	// failure alongside the partial result, because a half-completed diagnosis
	// beats no diagnosis.
	Run(ctx context.Context, st *model.State) error
}

// Registry is an ordered set of probes.
type Registry struct {
	probes []Probe
}

// NewRegistry builds a Registry.
func NewRegistry(ps ...Probe) *Registry {
	return &Registry{probes: append([]Probe(nil), ps...)}
}

// Add appends a probe.
func (r *Registry) Add(p Probe) { r.probes = append(r.probes, p) }

// All returns the probes in run order.
func (r *Registry) All() []Probe { return r.probes }

// Names returns the probe identifiers in run order.
func (r *Registry) Names() []string {
	out := make([]string, 0, len(r.probes))
	for _, p := range r.probes {
		out = append(out, p.Name())
	}
	return out
}
