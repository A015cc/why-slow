//go:build linux

package path

import (
	"net"
	"os"
)

// DefaultGateway returns the host's default IPv4 gateway, or ok=false when it
// cannot be determined.
//
// Linux is the one platform with a clean, non-localized, privilege-free source:
// /proc/net/route. Everywhere else why-slow deliberately reports "unknown"
// instead of scraping `ipconfig`, `route` or PowerShell. That output is
// localized — this tool is run on Chinese Windows, where a gateway line reads
// "默认网关" — so parsing it is a correctness landmine. A missing gateway costs
// the report a sentence; a wrong one costs it its credibility.
func DefaultGateway() (net.IP, bool) {
	f, err := os.Open("/proc/net/route")
	if err != nil {
		return nil, false
	}
	defer f.Close()
	return parseProcNetRoute(f)
}
