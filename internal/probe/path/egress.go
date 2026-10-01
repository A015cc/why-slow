package path

import (
	"context"
	"errors"
	"net"

	"github.com/A015cc/why-slow/internal/netsys"
)

// errNoEgressSource is returned when the kernel never commits to a source
// address, even after the fallback send.
var errNoEgressSource = errors.New("path: kernel did not select a source address")

// egressSource determines the local source address the kernel would use to reach
// remoteIP, using the connected-UDP-socket trick.
//
// Opening a UDP socket and connect()ing it to a destination runs the kernel's
// full route lookup — selecting the outgoing interface and source address —
// without sending a single packet and without any privilege. It works the same
// way on Windows, Linux and macOS, which is why it is used here instead of
// platform routing APIs.
//
// Windows caveat, and the reason the send is part of the design rather than
// bolted on afterwards: the Windows stack is allowed to defer source-address
// selection until the first real send, and until then getsockname() can
// legitimately report 0.0.0.0. So when LocalAddr() comes back unspecified we
// send exactly one byte to the real remote address and re-read LocalAddr(); by
// then the kernel has committed. The single byte is the price of correctness,
// which is why this function takes an already-resolved IP and a concrete port
// rather than a hostname.
func egressSource(ctx context.Context, dial netsys.DialFunc, remoteIP net.IP, port string) (net.IP, error) {
	if remoteIP == nil {
		return nil, errors.New("path: nil remote IP")
	}
	if port == "" {
		port = defaultProbePort
	}
	conn, err := dial(ctx, "udp", net.JoinHostPort(remoteIP.String(), port))
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if ip := addrIP(conn.LocalAddr()); ip != nil && !ip.IsUnspecified() {
		return ip, nil
	}

	// Designed fallback: force the kernel to commit to a source address.
	if _, err := conn.Write([]byte{0}); err != nil {
		return nil, err
	}
	if ip := addrIP(conn.LocalAddr()); ip != nil && !ip.IsUnspecified() {
		return ip, nil
	}
	return nil, errNoEgressSource
}

// addrIP extracts an IP from a net.Addr, tolerating a nil value and unexpected
// concrete types.
func addrIP(a net.Addr) net.IP {
	switch v := a.(type) {
	case *net.UDPAddr:
		if v == nil {
			return nil
		}
		return v.IP
	case *net.TCPAddr:
		if v == nil {
			return nil
		}
		return v.IP
	}
	if a == nil {
		return nil
	}
	if host, _, err := net.SplitHostPort(a.String()); err == nil {
		return net.ParseIP(host)
	}
	return net.ParseIP(a.String())
}
