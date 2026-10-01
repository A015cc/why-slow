package path

import (
	"bufio"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
)

// defaultProbePort is a real, rarely-filtered remote port. The UDP connect()
// trick never sends a packet, but the Windows fallback does, and it must be a
// port that plausibly exists so the kernel commits to a source address instead
// of failing the send.
const defaultProbePort = "443"

// subjectDefault is the fixed subject used for host-wide facts such as the
// default gateway.
const subjectDefault = "default"

// normalizeTarget splits a user-supplied target into a bare host and a port.
//
// It accepts "host", "host:port", "1.1.1.1", "[2606:4700::1111]" and
// "[2606:4700::1111]:443"; anything without an explicit port gets
// defaultProbePort. It is deliberately lenient: a malformed target must never
// panic, it is simply treated as a bare host. That leniency is why the parser
// is a pure function with its own test.
func normalizeTarget(target string) (host, port string) {
	t := strings.TrimSpace(target)
	if t == "" {
		return "", defaultProbePort
	}
	// Tolerate a full URL being pasted in as the target.
	if i := strings.Index(t, "://"); i >= 0 {
		t = t[i+3:]
	}
	if i := strings.IndexAny(t, "/?#"); i >= 0 {
		t = t[:i]
	}
	if h, p, err := net.SplitHostPort(t); err == nil {
		if p == "" {
			p = defaultProbePort
		}
		return strings.Trim(h, "[]"), p
	}
	// No parseable port. An IPv6 literal such as 2606:4700::1111 is full of
	// colons but has no port; SplitHostPort rejects it, and we must not then
	// mistake part of the address for a port by hand-splitting on ":".
	return strings.Trim(t, "[]"), defaultProbePort
}

// NormalizeTarget exposes normalizeTarget so other probes parse targets exactly
// the way this one does. The latency probe dials a resolved IP literal but still
// has to split the user's argument into host and port, and two parsers that
// disagree about "[::1]:443" would be a bug waiting to happen.
func NormalizeTarget(target string) (host, port string) { return normalizeTarget(target) }

// boolText is the canonical encoding for boolean observations. Rules compare
// these strings literally, so it is defined once, here.
func boolText(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// kindOf labels an interface as either the virtual kind ClassifyVirtual found or
// plain "physical".
func kindOf(virtual bool, kind string) string {
	if !virtual {
		return "physical"
	}
	if kind == "" {
		return "virtual"
	}
	return kind
}

// joinAddrs renders an interface's addresses as a stable, comma-joined string.
// Nil entries are skipped rather than rendered as "<nil>".
func joinAddrs(addrs []net.Addr) string {
	parts := make([]string, 0, len(addrs))
	for _, a := range addrs {
		if a == nil {
			continue
		}
		if s := strings.TrimSpace(a.String()); s != "" {
			parts = append(parts, s)
		}
	}
	return strings.Join(parts, ",")
}

// joinIPs renders IPs comma-joined, skipping nils and empty values.
func joinIPs(ips []net.IP) string {
	parts := make([]string, 0, len(ips))
	for _, ip := range ips {
		if ip == nil {
			continue
		}
		parts = append(parts, ip.String())
	}
	return strings.Join(parts, ",")
}

// parseProcNetRoute reads a Linux /proc/net/route table and returns the default
// gateway.
//
// It is a pure function so it can be exercised on any platform, including the
// Windows development machines this tool is built on. The format is a kernel
// interface, not localized program output — which is exactly why it is safe to
// parse when `ipconfig` and PowerShell output are not.
//
// Columns (whitespace separated):
//
//	Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT
//
// Addresses are 8 hex digits in little-endian byte order. The default route has
// Destination and Mask both zero. Anything that does not parse is skipped, so a
// malformed table yields ok=false rather than an error or a panic.
func parseProcNetRoute(r io.Reader) (net.IP, bool) {
	sc := bufio.NewScanner(r)
	first := true
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if first {
			first = false
			if len(fields) > 0 && strings.EqualFold(fields[0], "Iface") {
				continue // header row
			}
		}
		if len(fields) < 8 {
			continue
		}
		dest, err := parseHexLE4(fields[1])
		if err != nil || dest != 0 {
			continue
		}
		mask, err := parseHexLE4(fields[7])
		if err != nil || mask != 0 {
			continue
		}
		gw, err := parseHexLE4(fields[2])
		if err != nil || gw == 0 {
			continue
		}
		return ipFromHexLE4(gw), true
	}
	return nil, false
}

// parseHexLE4 parses an 8-hex-digit little-endian address into a uint32 whose
// least-significant byte is the first address octet.
func parseHexLE4(s string) (uint32, error) {
	if len(s) != 8 {
		return 0, errors.New("path: not an 8-hex-digit address")
	}
	v, err := strconv.ParseUint(s, 16, 32)
	if err != nil {
		return 0, err
	}
	return uint32(v), nil
}

// ipFromHexLE4 converts the little-endian word produced by parseHexLE4 into an
// IPv4 address.
func ipFromHexLE4(v uint32) net.IP {
	return net.IPv4(byte(v), byte(v>>8), byte(v>>16), byte(v>>24))
}
