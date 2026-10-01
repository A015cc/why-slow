package netsys

import (
	"net"
	"strings"
)

// Iface describes a network interface in the terms that matter to diagnosis.
type Iface struct {
	Name     string
	Index    int
	MTU      int
	Up       bool
	Loopback bool
	Addrs    []net.Addr
	// Virtual marks adapters that are not physical hardware. Traffic leaving
	// through one of these is being intercepted by a tunnel, VPN or accelerator,
	// which changes what any latency number means.
	Virtual bool
	Kind    string
}

// AddrsOf returns the interface's addresses, optionally filtered to one family.
func (i Iface) IPs() []net.IP {
	var out []net.IP
	for _, a := range i.Addrs {
		if ipn, ok := a.(*net.IPNet); ok {
			out = append(out, ipn.IP)
		}
	}
	return out
}

// virtualHints maps substrings of an adapter name to what that adapter is.
//
// Matching is on the name rather than a numeric interface type on purpose:
// interface type codes are OS-specific and the descriptive names are stable,
// vendor-supplied and not localized. That last property matters here, because
// this tool runs on Chinese Windows where localized output is a real hazard —
// a physical adapter named "以太网 4" correctly matches nothing and is therefore
// correctly treated as physical.
var virtualHints = []struct{ needle, kind string }{
	{"wintun", "Wintun TUN (WireGuard-style)"},
	{"tap-windows", "OpenVPN TAP"},
	{"aavktap", "VeryKuai accelerator TAP"},
	{"vkddpi", "VeryKuai packet filter"},
	{"tailscale", "Tailscale tunnel"},
	{"wireguard", "WireGuard tunnel"},
	{"openvpn", "OpenVPN tunnel"},
	{"zerotier", "ZeroTier tunnel"},
	{"utun", "utun tunnel"},
	{"clash", "Clash TUN"},
	{"singbox", "sing-box TUN"},
	{"sing-box", "sing-box TUN"},
	{"xray", "Xray TUN"},
	{"v2ray", "v2ray TUN"},
	{"nebuladriver", "game accelerator driver"},
	{"vmware", "VMware virtual adapter"},
	{"virtualbox", "VirtualBox virtual adapter"},
	{"hyper-v", "Hyper-V virtual switch"},
	{"vethernet", "Hyper-V virtual switch"},
	{"hamachi", "LogMeIn Hamachi"},
	{"radmin", "Radmin VPN"},
	{"nordlynx", "NordVPN tunnel"},
	{"proton", "Proton VPN tunnel"},
	{"mullvad", "Mullvad tunnel"},
	{"xrelay", "Xrelay proxy driver"},
}

// ClassifyVirtual reports whether an adapter name looks like a virtual one, and
// what kind. It is exported so the rule engine can explain the classification.
func ClassifyVirtual(name string) (bool, string) {
	lower := strings.ToLower(name)
	for _, h := range virtualHints {
		if strings.Contains(lower, h.needle) {
			return true, h.kind
		}
	}
	return false, ""
}

// Interfaces enumerates the host's network interfaces.
func Interfaces() ([]Iface, error) {
	list, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	out := make([]Iface, 0, len(list))
	for _, ni := range list {
		addrs, err := ni.Addrs()
		if err != nil {
			// A single unreadable interface must not sink the enumeration.
			addrs = nil
		}
		virtual, kind := ClassifyVirtual(ni.Name)
		out = append(out, Iface{
			Name:     ni.Name,
			Index:    ni.Index,
			MTU:      ni.MTU,
			Up:       ni.Flags&net.FlagUp != 0,
			Loopback: ni.Flags&net.FlagLoopback != 0,
			Addrs:    addrs,
			Virtual:  virtual,
			Kind:     kind,
		})
	}
	return out, nil
}

// ByIndex finds an interface by its index.
func ByIndex(ifaces []Iface, idx int) (Iface, bool) {
	for _, i := range ifaces {
		if i.Index == idx {
			return i, true
		}
	}
	return Iface{}, false
}

// ByIP finds the interface holding a given address.
func ByIP(ifaces []Iface, ip net.IP) (Iface, bool) {
	for _, i := range ifaces {
		for _, have := range i.IPs() {
			if have.Equal(ip) {
				return i, true
			}
		}
	}
	return Iface{}, false
}
