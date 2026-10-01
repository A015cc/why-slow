//go:build linux

package ipv6

import "os"

// defaultRouteV6 reports whether a default IPv6 route exists. Only Linux has a
// clean, non-localized, privilege-free source: /proc/net/ipv6_route. Elsewhere
// why-slow reports nothing rather than shelling out to localization-sensitive
// tools — an absent key means unknown, which the rules handle honestly.
func defaultRouteV6() (hasDefault, ok bool) {
	f, err := os.Open("/proc/net/ipv6_route")
	if err != nil {
		return false, false
	}
	defer f.Close()
	return parseProcNetIPv6Route(f)
}
