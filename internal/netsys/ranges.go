// Package netsys is the layer that touches the operating system: interfaces,
// routing, DNS, raw sockets and HTTP. Everything here is shaped so it can be
// substituted in tests, because the interesting logic elsewhere should not need
// a real network to be exercised.
package netsys

import "net"

func mustCIDR(s string) *net.IPNet {
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		panic("netsys: bad CIDR " + s + ": " + err.Error())
	}
	return n
}

var (
	// RFC1918 private space. A gateway inside one of these means NAT is
	// happening, but only at the local router.
	privBlocks = []*net.IPNet{
		mustCIDR("10.0.0.0/8"),
		mustCIDR("172.16.0.0/12"),
		mustCIDR("192.168.0.0/16"),
	}
	// RFC6598 carrier-grade NAT. A gateway here is the cleanest single signal
	// that the ISP is NATing too, so inbound connections are impossible without
	// a relay or hole punching.
	cgnatBlock = mustCIDR("100.64.0.0/10")

	ulaBlock     = mustCIDR("fc00::/7") // RFC4193 unique local: private by construction
	linkLocalV6  = mustCIDR("fe80::/10")
	globalV6     = mustCIDR("2000::/3") // the only range that is globally routable
	teredoBlock  = mustCIDR("2001::/32")
	sixToFourNet = mustCIDR("2002::/16")

	// Transition mechanisms that present as IPv6 but generally perform worse
	// than plain IPv4. Worth naming so the report can say which one is in use.
	linkLocalV4 = mustCIDR("169.254.0.0/16")
	loopV4      = mustCIDR("127.0.0.0/8")
	loopV6      = mustCIDR("::1/128")
)

func inAny(ip net.IP, blocks ...*net.IPNet) bool {
	for _, b := range blocks {
		if b.Contains(ip) {
			return true
		}
	}
	return false
}

// IsPrivate reports whether ip is in RFC1918 space.
func IsPrivate(ip net.IP) bool {
	v4 := ip.To4()
	if v4 == nil {
		return false
	}
	return inAny(v4, privBlocks...)
}

// IsCGNAT reports whether ip is in RFC6598 carrier-grade NAT space.
func IsCGNAT(ip net.IP) bool {
	v4 := ip.To4()
	if v4 == nil {
		return false
	}
	return cgnatBlock.Contains(v4)
}

// IsLoopback reports whether ip is a loopback address.
func IsLoopback(ip net.IP) bool {
	if ip.IsLoopback() {
		return true
	}
	if v4 := ip.To4(); v4 != nil {
		return loopV4.Contains(v4)
	}
	return loopV6.Contains(ip)
}

// IsLinkLocal reports whether ip is link-local in either family.
func IsLinkLocal(ip net.IP) bool {
	if v4 := ip.To4(); v4 != nil {
		return linkLocalV4.Contains(v4)
	}
	return linkLocalV6.Contains(ip)
}

// IsULA reports whether ip is an IPv6 unique local address.
func IsULA(ip net.IP) bool {
	if ip.To4() != nil {
		return false
	}
	return ulaBlock.Contains(ip)
}

// IsGlobalUnicastV6 reports whether ip is a globally routable IPv6 address.
// This is the check that matters for "can IPv6 actually carry traffic": a host
// with only fe80:: and an fc00:: address has IPv6 configured but not usable.
func IsGlobalUnicastV6(ip net.IP) bool {
	if ip.To4() != nil {
		return false
	}
	return globalV6.Contains(ip)
}

// IsTeredo reports whether ip is a Teredo tunnel address.
func IsTeredo(ip net.IP) bool {
	if ip.To4() != nil {
		return false
	}
	return teredoBlock.Contains(ip)
}

// Is6to4 reports whether ip is a 6to4 tunnel address.
func Is6to4(ip net.IP) bool {
	if ip.To4() != nil {
		return false
	}
	return sixToFourNet.Contains(ip)
}

// DescribeAddr labels an address with the role it plays, so reports can explain
// why an address does or does not count as connectivity.
func DescribeAddr(ip net.IP) string {
	switch {
	case ip == nil:
		return "none"
	case IsLoopback(ip):
		return "loopback"
	case IsLinkLocal(ip):
		return "link-local (not routable)"
	case IsCGNAT(ip):
		return "carrier-grade NAT (RFC6598)"
	case IsPrivate(ip):
		return "private (RFC1918)"
	case IsULA(ip):
		return "unique local (RFC4193, not globally routable)"
	case IsTeredo(ip):
		return "Teredo tunnel (deprecated, usually slower than IPv4)"
	case Is6to4(ip):
		return "6to4 tunnel (deprecated, usually slower than IPv4)"
	case IsGlobalUnicastV6(ip):
		return "global unicast IPv6"
	default:
		return "global unicast IPv4"
	}
}
