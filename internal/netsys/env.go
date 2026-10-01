package netsys

import (
	"context"
	"net"
	"net/http"
	"time"
)

// DialFunc matches net.Dialer.DialContext. Note that it returns only once the
// connection is established, which is what makes wrapping it in a timer a
// measurement of the handshake.
type DialFunc func(ctx context.Context, network, address string) (net.Conn, error)

// Env carries every OS-facing dependency the probes need, so tests can supply
// fakes instead of requiring a network. Probes take an *Env rather than calling
// package-level functions directly for exactly this reason.
type Env struct {
	Dial     DialFunc
	Resolver *net.Resolver
	HTTP     *http.Client
	Now      func() time.Time
	Ifaces   func() ([]Iface, error)
	// PublicIPTimeout bounds each external IP-echo request.
	PublicIPTimeout time.Duration
}

// DefaultEnv returns an Env wired to the real operating system.
func DefaultEnv() *Env {
	d := &net.Dialer{Timeout: 5 * time.Second}
	return &Env{
		Dial:            d.DialContext,
		Resolver:        net.DefaultResolver,
		HTTP:            DirectClient(10 * time.Second),
		Now:             time.Now,
		Ifaces:          Interfaces,
		PublicIPTimeout: 10 * time.Second,
	}
}

// ContextDialer adapts the Env's Dial into something usable with a custom
// net.Dialer when a probe needs to set socket options.
func (e *Env) ContextDialer() *net.Dialer { return &net.Dialer{Timeout: 5 * time.Second} }
