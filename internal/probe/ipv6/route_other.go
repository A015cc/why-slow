//go:build !linux

package ipv6

// defaultRouteV6 is deliberately unsupported off Linux: there is no portable,
// non-localized, dependency-free way to read it. The probe then omits
// ipv6.default_route entirely, and the rules read that omission as unknown
// rather than as "no route" — the same honesty rule the path probe applies to
// the default gateway.
func defaultRouteV6() (hasDefault, ok bool) { return false, false }
