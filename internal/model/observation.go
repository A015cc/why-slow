// Package model defines the data types that flow through why-slow.
//
// The pipeline has three hard boundaries:
//
//		probe --> Observation --> verdict rules --> Finding --> render
//
//	 1. Probes emit Observations only. A probe never decides what a measurement
//	    means, because the most useful conclusions combine evidence from several
//	    probes at once ("latency shows a 1s cluster AND path shows egress via a
//	    TUN, so we may be timing the tunnel, not the link"). A single probe
//	    cannot know that.
//	 2. Rules are pure functions over State: no network, no clock, fully
//	    testable without a network stack.
//	 3. Renderers consume Findings structurally and never learn a probe's name.
package model

import "time"

// Observation is a single measured fact. It carries provenance in Meta so a
// finding can always be traced back to how the number was obtained.
type Observation struct {
	Probe   string            `json:"probe"`
	Subject string            `json:"subject"`
	Key     string            `json:"key"`
	Unit    string            `json:"unit,omitempty"`
	Num     float64           `json:"num,omitempty"`
	Series  []float64         `json:"series,omitempty"`
	Text    string            `json:"text,omitempty"`
	At      time.Time         `json:"at"`
	Meta    map[string]string `json:"meta,omitempty"`
}

// Num builds a scalar observation.
func Num(probe, subject, key, unit string, v float64, meta map[string]string) Observation {
	return Observation{Probe: probe, Subject: subject, Key: key, Unit: unit, Num: v, At: time.Now(), Meta: meta}
}

// Series builds an observation holding a set of samples.
func Series(probe, subject, key, unit string, vs []float64, meta map[string]string) Observation {
	return Observation{Probe: probe, Subject: subject, Key: key, Unit: unit, Series: vs, At: time.Now(), Meta: meta}
}

// Text builds a label-valued observation, for facts that are not numbers.
func Text(probe, subject, key, v string, meta map[string]string) Observation {
	return Observation{Probe: probe, Subject: subject, Key: key, Text: v, At: time.Now(), Meta: meta}
}

const idxSep = "\x00"

func key3(p, k, s string) string { return p + idxSep + k + idxSep + s }
func key2(p, k string) string    { return p + idxSep + k }

// State is a queryable collection of observations. Rules read from it; nothing
// else writes to it.
type State struct {
	obs    []Observation
	byFull map[string][]int
	byPK   map[string][]int
}

// NewState returns an empty State.
func NewState() *State {
	return &State{byFull: map[string][]int{}, byPK: map[string][]int{}}
}

// Add appends observations, stamping any missing timestamp.
func (s *State) Add(obs ...Observation) {
	for _, o := range obs {
		if o.At.IsZero() {
			o.At = time.Now()
		}
		i := len(s.obs)
		s.byFull[key3(o.Probe, o.Key, o.Subject)] = append(s.byFull[key3(o.Probe, o.Key, o.Subject)], i)
		s.byPK[key2(o.Probe, o.Key)] = append(s.byPK[key2(o.Probe, o.Key)], i)
		s.obs = append(s.obs, o)
	}
}

// All returns every observation in insertion order.
func (s *State) All() []Observation { return s.obs }

// One returns the last observation matching probe/key/subject exactly.
func (s *State) One(probe, key, subject string) (Observation, bool) {
	idx := s.byFull[key3(probe, key, subject)]
	if len(idx) == 0 {
		return Observation{}, false
	}
	return s.obs[idx[len(idx)-1]], true
}

// Has reports whether an exact probe/key/subject observation exists.
func (s *State) Has(probe, key, subject string) bool {
	return len(s.byFull[key3(probe, key, subject)]) > 0
}

// Num returns the scalar value of an exact match.
func (s *State) Num(probe, key, subject string) (float64, bool) {
	o, ok := s.One(probe, key, subject)
	if !ok {
		return 0, false
	}
	return o.Num, true
}

// TextOf returns the text value of an exact match.
func (s *State) TextOf(probe, key, subject string) (string, bool) {
	o, ok := s.One(probe, key, subject)
	if !ok || o.Text == "" {
		return "", false
	}
	return o.Text, true
}

// Series returns the sample set of an exact match.
func (s *State) Series(probe, key, subject string) []float64 {
	o, ok := s.One(probe, key, subject)
	if !ok {
		return nil
	}
	return o.Series
}

// Subjects returns the distinct subjects seen for a probe/key pair.
func (s *State) Subjects(probe, key string) []string {
	seen := map[string]bool{}
	var out []string
	for _, i := range s.byPK[key2(probe, key)] {
		if sub := s.obs[i].Subject; !seen[sub] {
			seen[sub] = true
			out = append(out, sub)
		}
	}
	return out
}

// Texts collects every text value for a probe/key across all subjects, which is
// how per-interface style observations are read back.
func (s *State) Texts(probe, key string) map[string]string {
	out := map[string]string{}
	for _, i := range s.byPK[key2(probe, key)] {
		out[s.obs[i].Subject] = s.obs[i].Text
	}
	return out
}

// Nums collects every scalar value for a probe/key across all subjects.
func (s *State) Nums(probe, key string) map[string]float64 {
	out := map[string]float64{}
	for _, i := range s.byPK[key2(probe, key)] {
		out[s.obs[i].Subject] = s.obs[i].Num
	}
	return out
}
