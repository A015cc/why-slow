//go:build !linux

package path

import "net"

// DefaultGateway is deliberately unsupported off Linux.
//
// On Windows the documented way to find the default route is GetBestRoute2 in
// iphlpapi.dll, reachable only through cgo or a syscall package the project does
// not depend on; on macOS and BSD it means shelling out to `route -n get
// default`. Both cost more than the fact is worth here, and parsing localized
// `ipconfig` output is explicitly off the table. Reporting "unknown" is the
// honest answer: the probe then records no `gateway` observation at all, and the
// rules read that absence as unknown rather than as "no gateway".
func DefaultGateway() (net.IP, bool) { return nil, false }
