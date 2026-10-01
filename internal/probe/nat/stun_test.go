package nat

import (
	"encoding/binary"
	"net"
	"testing"
)

func txIDFrom(b ...byte) [12]byte {
	var tx [12]byte
	copy(tx[:], b)
	return tx
}

func TestDecodeXORMappedAddressV4(t *testing.T) {
	// Mapped 192.0.2.1:32853.
	val := []byte{0x00, stunAddrV4, 0xA1, 0x47, 0xE1, 0x12, 0xA6, 0x43}
	ip, port, err := decodeXORMappedAddress(val, txIDFrom())
	if err != nil {
		t.Fatal(err)
	}
	if !ip.Equal(net.ParseIP("192.0.2.1")) {
		t.Fatalf("ip = %v, want 192.0.2.1", ip)
	}
	if port != 32853 {
		t.Fatalf("port = %d, want 32853", port)
	}
}

func TestDecodeXORMappedAddressV6(t *testing.T) {
	// Mapped [2001:db8::1]:50000, XORed with cookie+txID where txID is 0x00..0x0b.
	tx := txIDFrom(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11)
	val := []byte{
		0x00, stunAddrV6, 0xE2, 0x42,
		0x01, 0x13, 0xA9, 0xFA,
		0x00, 0x01, 0x02, 0x03,
		0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0A, 0x0A,
	}
	ip, port, err := decodeXORMappedAddress(val, tx)
	if err != nil {
		t.Fatal(err)
	}
	if !ip.Equal(net.ParseIP("2001:db8::1")) {
		t.Fatalf("ip = %v, want 2001:db8::1", ip)
	}
	if port != 50000 {
		t.Fatalf("port = %d, want 50000", port)
	}
}

func TestDecodeXORMappedAddressErrors(t *testing.T) {
	tx := txIDFrom()
	if _, _, err := decodeXORMappedAddress([]byte{0x00, 0x01, 0x00}, tx); err == nil {
		t.Error("short value: expected error")
	}
	if _, _, err := decodeXORMappedAddress([]byte{0x00, 0x01, 0x00, 0x00}, tx); err == nil {
		t.Error("short IPv4 value: expected error")
	}
	if _, _, err := decodeXORMappedAddress([]byte{0x00, 0x02, 0x00, 0x00, 0x00}, tx); err == nil {
		t.Error("short IPv6 value: expected error")
	}
	if _, _, err := decodeXORMappedAddress([]byte{0x00, 0x09, 0x00, 0x00}, tx); err == nil {
		t.Error("unknown family: expected error")
	}
}

// buildResponse fabricates a binding success response carrying the supplied
// attributes (type, value pairs).
func buildResponse(tx [12]byte, attrs ...[2][]byte) []byte {
	var body []byte
	for _, a := range attrs {
		typ := binary.BigEndian.Uint16(a[0])
		val := a[1]
		var hdr [4]byte
		binary.BigEndian.PutUint16(hdr[0:2], typ)
		binary.BigEndian.PutUint16(hdr[2:4], uint16(len(val)))
		body = append(body, hdr[:]...)
		body = append(body, val...)
		if pad := len(val) % 4; pad != 0 {
			body = append(body, make([]byte, 4-pad)...)
		}
	}
	out := make([]byte, stunHeaderLen)
	binary.BigEndian.PutUint16(out[0:2], stunBindingOK)
	binary.BigEndian.PutUint16(out[2:4], uint16(len(body)))
	binary.BigEndian.PutUint32(out[4:8], stunMagicCookie)
	copy(out[8:20], tx[:])
	return append(out, body...)
}

func xorMappedV4Value(ip net.IP, port int) []byte {
	v4 := ip.To4()
	cookie := make([]byte, 4)
	binary.BigEndian.PutUint32(cookie, stunMagicCookie)
	val := make([]byte, 8)
	val[1] = stunAddrV4
	binary.BigEndian.PutUint16(val[2:4], uint16(port)^uint16(stunMagicCookie>>16))
	for i := 0; i < 4; i++ {
		val[4+i] = v4[i] ^ cookie[i]
	}
	return val
}

func TestParseBindingResponseFindsXORMapped(t *testing.T) {
	tx := txIDFrom(9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 1, 2)
	// A SOFTWARE attribute (odd length, so padding is exercised) precedes the
	// XOR-MAPPED-ADDRESS.
	resp := buildResponse(tx,
		[2][]byte{{0x80, 0x22}, []byte("hello")},
		[2][]byte{{0x00, 0x20}, xorMappedV4Value(net.ParseIP("192.0.2.55"), 54321)},
	)
	ip, port, err := parseBindingResponse(resp, tx)
	if err != nil {
		t.Fatal(err)
	}
	if !ip.Equal(net.ParseIP("192.0.2.55")) || port != 54321 {
		t.Fatalf("got %v:%d", ip, port)
	}
}

func TestParseBindingResponseRejectsBadPackets(t *testing.T) {
	tx := txIDFrom(1, 2, 3)
	good := buildResponse(tx, [2][]byte{{0x00, 0x20}, xorMappedV4Value(net.ParseIP("192.0.2.1"), 1234)})

	// Wrong transaction ID.
	if _, _, err := parseBindingResponse(good, txIDFrom(1, 2, 4)); err == nil {
		t.Error("expected txID mismatch error")
	}

	// Wrong message type.
	badType := append([]byte(nil), good...)
	binary.BigEndian.PutUint16(badType[0:2], 0x0111)
	if _, _, err := parseBindingResponse(badType, tx); err == nil {
		t.Error("expected message-type error")
	}

	// Bad magic cookie.
	badCookie := append([]byte(nil), good...)
	binary.BigEndian.PutUint32(badCookie[4:8], 0xDEADBEEF)
	if _, _, err := parseBindingResponse(badCookie, tx); err == nil {
		t.Error("expected magic-cookie error")
	}

	// Truncated header.
	if _, _, err := parseBindingResponse(good[:10], tx); err == nil {
		t.Error("expected short-header error")
	}

	// Length field claims more than was received.
	badLen := append([]byte(nil), good...)
	binary.BigEndian.PutUint16(badLen[2:4], uint16(len(good)+100))
	if _, _, err := parseBindingResponse(badLen, tx); err == nil {
		t.Error("expected truncated-body error")
	}

	// No XOR-MAPPED-ADDRESS at all.
	noXor := buildResponse(tx, [2][]byte{{0x00, 0x06}, []byte("someone")})
	if _, _, err := parseBindingResponse(noXor, tx); err == nil {
		t.Error("expected missing-attribute error")
	}

	// Attribute length claims more than the body holds.
	overrun := append([]byte(nil), good...)
	binary.BigEndian.PutUint16(overrun[stunHeaderLen+2:stunHeaderLen+4], 0xFFFF)
	if _, _, err := parseBindingResponse(overrun, tx); err == nil {
		t.Error("expected truncated-attribute error")
	}
}

func TestBuildBindingRequest(t *testing.T) {
	b, tx, err := buildBindingRequest()
	if err != nil {
		t.Fatal(err)
	}
	if len(b) != stunHeaderLen {
		t.Fatalf("len = %d", len(b))
	}
	if binary.BigEndian.Uint16(b[0:2]) != stunBindingReq {
		t.Fatal("wrong message type")
	}
	if binary.BigEndian.Uint32(b[4:8]) != stunMagicCookie {
		t.Fatal("wrong magic cookie")
	}
	var got [12]byte
	copy(got[:], b[8:20])
	if got != tx {
		t.Fatal("transaction ID not embedded in packet")
	}
}

// FuzzParseBindingResponse asserts the response parser never panics or
// over-reads on arbitrary network input. Run with:
//
//	go test ./internal/probe/nat -run=^$ -fuzz=FuzzParseBindingResponse
func FuzzParseBindingResponse(f *testing.F) {
	tx := txIDFrom(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12)
	f.Add(buildResponse(tx, [2][]byte{{0x00, 0x20}, xorMappedV4Value(net.ParseIP("192.0.2.1"), 1234)}), tx[:])
	f.Add(buildResponse(tx), tx[:])
	f.Add([]byte{}, []byte{})
	f.Add([]byte{0x01, 0x01, 0x00, 0x0C, 0x21, 0x12, 0xA4, 0x42}, tx[:])

	f.Fuzz(func(t *testing.T, b []byte, txb []byte) {
		var id [12]byte
		copy(id[:], txb)
		// Must not panic, must not hang, and must return a sane port range.
		_, port, _ := parseBindingResponse(b, id)
		if port < 0 || port > 65535 {
			t.Fatalf("port out of range: %d", port)
		}
	})
}

// FuzzDecodeXORMappedAddress reaches the decoder directly, since the outer
// parser only calls it for an otherwise well-formed packet.
func FuzzDecodeXORMappedAddress(f *testing.F) {
	f.Add([]byte{0x00, 0x01, 0xA1, 0x47, 0xE1, 0x12, 0xA6, 0x43}, make([]byte, 12))
	f.Add([]byte{}, make([]byte, 12))
	f.Fuzz(func(t *testing.T, v []byte, txb []byte) {
		var id [12]byte
		copy(id[:], txb)
		ip, port, err := decodeXORMappedAddress(v, id)
		if err != nil {
			return
		}
		if ip == nil {
			t.Fatal("nil IP with nil error")
		}
		if port < 0 || port > 65535 {
			t.Fatalf("port out of range: %d", port)
		}
	})
}
