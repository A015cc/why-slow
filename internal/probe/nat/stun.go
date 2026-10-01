package nat

import (
	"context"
	crand "crypto/rand"
	"encoding/binary"
	"errors"
	"net"
	"time"

	"github.com/A015cc/why-slow/internal/model"
	"github.com/A015cc/why-slow/internal/netsys"
)

// Minimal RFC 5389 (STUN) support. Only what is needed to learn the address a
// NAT maps our socket to: a binding request, and decoding of XOR-MAPPED-ADDRESS.
// Full NAT-type classification across several servers is deliberately out of
// scope — the mapped/local port pair is already the strong CGNAT signal, and it
// costs one round trip instead of several.
//
// STUN also earns its place next to the HTTP echo because it speaks raw UDP,
// which no HTTP proxy can intercept. On a machine whose proxy is a distant VPS,
// the STUN answer reflects the real path even when the HTTP answer cannot.

const (
	stunMagicCookie   uint32 = 0x2112A442
	stunBindingReq    uint16 = 0x0001
	stunBindingOK     uint16 = 0x0101
	stunAttrXORMapped uint16 = 0x0020
	stunHeaderLen            = 20
	stunAddrV4        uint8  = 0x01
	stunAddrV6        uint8  = 0x02
)

// stunServers are tried in order; the first that answers wins.
var stunServers = []string{
	"stun.cloudflare.com:3478",
	"stun.l.google.com:19302",
	"stun.miwifi.com:3478",
}

type stunResult struct {
	mappedIP   net.IP
	mappedPort int
	localPort  int
	server     string
	err        error
}

// buildBindingRequest assembles a minimal binding request: the 20-byte header
// and no attributes. Returns the packet and the transaction ID it embedded.
func buildBindingRequest() ([]byte, [12]byte, error) {
	var txID [12]byte
	if _, err := crand.Read(txID[:]); err != nil {
		return nil, txID, err
	}
	b := make([]byte, stunHeaderLen)
	binary.BigEndian.PutUint16(b[0:2], stunBindingReq)
	binary.BigEndian.PutUint16(b[2:4], 0) // no attributes
	binary.BigEndian.PutUint32(b[4:8], stunMagicCookie)
	copy(b[8:20], txID[:])
	return b, txID, nil
}

// parseBindingResponse validates a binding success response and returns the
// XOR-MAPPED-ADDRESS it carries.
//
// The input is fully untrusted network data, so every length is checked before
// it is used and a malformed packet yields an error rather than a panic or an
// over-read. This is the function the fuzz target hammers.
func parseBindingResponse(b []byte, txID [12]byte) (net.IP, int, error) {
	if len(b) < stunHeaderLen {
		return nil, 0, errors.New("stun: short header")
	}
	if binary.BigEndian.Uint16(b[0:2]) != stunBindingOK {
		return nil, 0, errors.New("stun: not a binding success response")
	}
	if binary.BigEndian.Uint32(b[4:8]) != stunMagicCookie {
		return nil, 0, errors.New("stun: bad magic cookie")
	}
	var got [12]byte
	copy(got[:], b[8:20])
	if got != txID {
		return nil, 0, errors.New("stun: transaction ID mismatch")
	}

	bodyLen := int(binary.BigEndian.Uint16(b[2:4]))
	if stunHeaderLen+bodyLen > len(b) {
		return nil, 0, errors.New("stun: truncated body")
	}
	body := b[stunHeaderLen : stunHeaderLen+bodyLen]

	for len(body) >= 4 {
		attrType := binary.BigEndian.Uint16(body[0:2])
		attrLen := int(binary.BigEndian.Uint16(body[2:4]))
		if attrLen > len(body)-4 {
			return nil, 0, errors.New("stun: truncated attribute")
		}
		val := body[4 : 4+attrLen]
		if attrType == stunAttrXORMapped {
			return decodeXORMappedAddress(val, txID)
		}
		// Attribute values are padded to a 4-byte boundary; the length field
		// does not include the padding.
		adv := 4 + attrLen
		if pad := adv % 4; pad != 0 {
			adv += 4 - pad
		}
		if adv > len(body) {
			break
		}
		body = body[adv:]
	}
	return nil, 0, errors.New("stun: no XOR-MAPPED-ADDRESS")
}

// decodeXORMappedAddress decodes an XOR-MAPPED-ADDRESS attribute value.
//
// RFC 5389 §15.2: the port is XORed with the top 16 bits of the magic cookie;
// an IPv4 address is XORed with the whole cookie; an IPv6 address is XORed with
// the cookie followed by the 12-byte transaction ID.
func decodeXORMappedAddress(v []byte, txID [12]byte) (net.IP, int, error) {
	if len(v) < 4 {
		return nil, 0, errors.New("stun: short XOR-MAPPED-ADDRESS")
	}
	port := int(binary.BigEndian.Uint16(v[2:4]) ^ uint16(stunMagicCookie>>16))

	switch v[1] {
	case stunAddrV4:
		if len(v) < 8 {
			return nil, 0, errors.New("stun: short IPv4 XOR-MAPPED-ADDRESS")
		}
		cookie := make([]byte, 4)
		binary.BigEndian.PutUint32(cookie, stunMagicCookie)
		ip := make(net.IP, net.IPv4len)
		for i := 0; i < net.IPv4len; i++ {
			ip[i] = v[4+i] ^ cookie[i]
		}
		return ip, port, nil
	case stunAddrV6:
		if len(v) < 20 {
			return nil, 0, errors.New("stun: short IPv6 XOR-MAPPED-ADDRESS")
		}
		mask := make([]byte, 16)
		binary.BigEndian.PutUint32(mask[0:4], stunMagicCookie)
		copy(mask[4:], txID[:])
		ip := make(net.IP, net.IPv6len)
		for i := 0; i < net.IPv6len; i++ {
			ip[i] = v[4+i] ^ mask[i]
		}
		return ip, port, nil
	default:
		return nil, 0, errors.New("stun: unknown address family")
	}
}

// lookupSTUN tries each server until one answers. Failures are expected on
// networks that block UDP; the caller records stun.error and moves on.
func (p *Probe) lookupSTUN(ctx context.Context, env *netsys.Env) stunResult {
	dial := dialFunc(env)
	var lastErr error
	for _, srv := range stunServers {
		ip, mappedPort, localPort, err := stunQuery(ctx, dial, srv)
		if err != nil {
			lastErr = err
			continue
		}
		return stunResult{mappedIP: ip, mappedPort: mappedPort, localPort: localPort, server: srv}
	}
	if lastErr == nil {
		lastErr = errors.New("stun: no servers configured")
	}
	return stunResult{err: lastErr}
}

// stunQuery performs one binding exchange over a connected UDP socket.
func stunQuery(ctx context.Context, dial netsys.DialFunc, server string) (net.IP, int, int, error) {
	conn, err := dial(ctx, "udp", server)
	if err != nil {
		return nil, 0, 0, err
	}
	defer conn.Close()

	req, txID, err := buildBindingRequest()
	if err != nil {
		return nil, 0, 0, err
	}
	if _, err := conn.Write(req); err != nil {
		return nil, 0, 0, err
	}

	localPort := 0
	if ua, ok := conn.LocalAddr().(*net.UDPAddr); ok {
		localPort = ua.Port
	}

	deadline := time.Now().Add(3 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if err := conn.SetReadDeadline(deadline); err != nil {
		return nil, 0, 0, err
	}

	buf := make([]byte, 1500)
	for {
		if err := ctx.Err(); err != nil {
			return nil, 0, 0, err
		}
		n, err := conn.Read(buf)
		if err != nil {
			return nil, 0, 0, err
		}
		ip, port, err := parseBindingResponse(buf[:n], txID)
		if err != nil {
			// A stray or malformed datagram: keep reading until the deadline.
			continue
		}
		return ip, port, localPort, nil
	}
}

// emitSTUN records the STUN observations under subject "stun".
func (p *Probe) emitSTUN(st *model.State, r stunResult) {
	const subj = "stun"
	if r.err != nil {
		st.Add(model.Text(probeName, subj, "stun.error", r.err.Error(), nil))
		return
	}
	md := map[string]string{"server": r.server}
	st.Add(
		model.Text(probeName, subj, "stun.mapped_ip", r.mappedIP.String(), md),
		model.Num(probeName, subj, "stun.mapped_port", "", float64(r.mappedPort), md),
		model.Num(probeName, subj, "stun.local_port", "", float64(r.localPort), md),
	)
}
