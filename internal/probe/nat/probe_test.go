package nat

import (
	"net"
	"strings"
	"testing"

	"github.com/A015cc/why-slow/internal/model"
	"github.com/A015cc/why-slow/internal/netsys"
)

func iface(name string, virtual bool, kind string, ips ...string) netsys.Iface {
	addrs := make([]net.Addr, 0, len(ips))
	for _, s := range ips {
		ip := net.ParseIP(s)
		bits := 32
		if ip.To4() == nil {
			bits = 128
		}
		addrs = append(addrs, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
	}
	return netsys.Iface{Name: name, Virtual: virtual, Kind: kind, Addrs: addrs}
}

func conclude(t *testing.T, ifaces []netsys.Iface) *model.State {
	t.Helper()
	env := &netsys.Env{Ifaces: func() ([]netsys.Iface, error) { return ifaces, nil }}
	p := New(env)
	st := model.NewState()
	p.emitConclusion(env, st, publicResult{})
	return st
}

func cgnatValue(t *testing.T, st *model.State) string {
	t.Helper()
	// TextOf is (probe, key, subject) — the subject here is the fixed "nat".
	v, ok := st.TextOf(probeName, "nat.cgnat", "nat")
	if !ok {
		t.Fatal("no nat.cgnat observation was recorded")
	}
	return v
}

// An overlay network hands out addresses from 100.64.0.0/10 on purpose, and
// Tailscale in particular does. Counting one as evidence of carrier NAT reports
// the user's own VPN as their ISP's NAT — and then advises them to work around
// it with the VPN they are already running.
func TestVirtualTunnelAddressIsNotCarrierNAT(t *testing.T) {
	st := conclude(t, []netsys.Iface{
		iface("Tailscale", true, "Tailscale tunnel", "100.64.0.9"),
		iface("以太网 4", false, "", "192.168.1.10"),
	})
	if got := cgnatValue(t, st); got == "true" {
		t.Error("a Tailscale address in 100.64.0.0/10 was reported as carrier-grade NAT")
	}
	reason, _ := st.TextOf(probeName, "nat.reason", "nat")
	if !strings.Contains(reason, "100.64.0.9") {
		t.Errorf("the ignored address is not mentioned, so the reasoning is invisible: %q", reason)
	}
	if !strings.Contains(reason, "tunnel") {
		t.Errorf("the reason does not explain why the address was ignored: %q", reason)
	}
}

// The same address on real hardware is exactly the evidence this probe is
// looking for, so the fix must not disarm the detection it was built for.
func TestPhysicalCGNATAddressIsStillReported(t *testing.T) {
	st := conclude(t, []netsys.Iface{
		iface("Tailscale", true, "Tailscale tunnel", "100.64.0.9"),
		iface("以太网 4", false, "", "100.64.0.1", "192.168.1.10"),
	})
	if got := cgnatValue(t, st); got != "true" {
		t.Errorf("nat.cgnat = %q, want true for a physical address in 100.64.0.0/10", got)
	}
}

func TestNoCGNATEvidenceIsUnknownNotFalse(t *testing.T) {
	st := conclude(t, []netsys.Iface{
		iface("以太网 4", false, "", "192.168.1.10"),
		iface("Tailscale", true, "Tailscale tunnel", "100.64.0.9"),
	})
	// "false" would mean "proven absent", which a host cannot prove about the
	// ISP side of its own router.
	if got := cgnatValue(t, st); got != "unknown" {
		t.Errorf("nat.cgnat = %q, want unknown", got)
	}
}
