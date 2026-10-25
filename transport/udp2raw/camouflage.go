package udp2raw

import (
	crand "crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"sync"
)

// TLS record content types.
const (
	tlsChangeCipherSpec = 0x14
	tlsHandshake        = 0x16
	tlsApplicationData  = 0x17

	// tlsMaxRecord is the largest record a peer may legally send.
	tlsMaxRecord = 16384
)

var errBadTLSRecord = errors.New("udp2raw: malformed tls record")

// tlsRecord renders one TLS record.
func tlsRecord(contentType byte, version uint16, payload []byte) []byte {
	b := make([]byte, 0, 5+len(payload))
	b = append(b, contentType, byte(version>>8), byte(version))
	b = binary.BigEndian.AppendUint16(b, uint16(len(payload)))
	return append(b, payload...)
}

// readTLSRecord reads one record from a stream.
func readTLSRecord(r io.Reader) (byte, []byte, error) {
	var hdr [5]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, nil, err
	}
	n := int(binary.BigEndian.Uint16(hdr[3:]))
	if n > tlsMaxRecord+2048 {
		return 0, nil, errBadTLSRecord
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return 0, nil, err
	}
	return hdr[0], buf, nil
}

// camoState turns frames into TLS-looking records and performs a cosmetic
// handshake. It is not a TLS implementation: nothing is authenticated or
// encrypted here, the QUIC layer above already does that.
type camoState struct {
	client bool
	sni    string

	mu          sync.Mutex
	hello       []byte
	flightSent  bool
	established bool
}

func newCamoState(sni string, client bool) *camoState {
	if sni == "" {
		sni = "www.example.com"
	}
	return &camoState{client: client, sni: sni}
}

// wrap returns the application-data record for one frame.
func (c *camoState) wrap(frame []byte) []byte {
	return tlsRecord(tlsApplicationData, 0x0303, frame)
}

// clientHello returns the (cached) ClientHello record.
func (c *camoState) clientHello() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.hello == nil {
		c.hello = buildClientHello(c.sni)
	}
	return c.hello
}

// splitTLSRecord validates one record and returns its content type and body.
func splitTLSRecord(rec []byte) (byte, []byte, bool) {
	if len(rec) < 5 {
		return 0, nil, false
	}
	n := int(binary.BigEndian.Uint16(rec[3:]))
	if n+5 > len(rec) {
		return 0, nil, false
	}
	return rec[0], rec[5 : 5+n], true
}

// ingest consumes one inbound record. It returns records the caller must send
// (the server's handshake flight) and, for application data, the frame payload.
func (c *camoState) ingest(contentType byte, body []byte) (send [][]byte, app []byte) {
	switch contentType {
	case tlsApplicationData:
		c.mu.Lock()
		c.established = true
		c.mu.Unlock()
		return nil, body
	case tlsHandshake, tlsChangeCipherSpec:
		c.mu.Lock()
		defer c.mu.Unlock()
		if !c.client && !c.flightSent {
			c.flightSent = true
			return serverFlight(), nil
		}
		return nil, nil
	default:
		return nil, nil
	}
}

func ext(kind uint16, body []byte) []byte {
	b := binary.BigEndian.AppendUint16(nil, kind)
	b = binary.BigEndian.AppendUint16(b, uint16(len(body)))
	return append(b, body...)
}

func u24(v int) []byte { return []byte{byte(v >> 16), byte(v >> 8), byte(v)} }

func randBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := crand.Read(b); err != nil {
		panic("udp2raw: no randomness available: " + err.Error())
	}
	return b
}

func buildClientHello(sni string) []byte {
	body := []byte{0x03, 0x03}
	body = append(body, randBytes(32)...)
	body = append(body, 32)
	body = append(body, randBytes(32)...)

	suites := []uint16{0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030}
	body = binary.BigEndian.AppendUint16(body, uint16(len(suites)*2))
	for _, s := range suites {
		body = binary.BigEndian.AppendUint16(body, s)
	}
	body = append(body, 1, 0) // null compression

	var exts []byte
	name := []byte(sni)
	sniBody := binary.BigEndian.AppendUint16(nil, uint16(len(name)+3))
	sniBody = append(sniBody, 0)
	sniBody = binary.BigEndian.AppendUint16(sniBody, uint16(len(name)))
	sniBody = append(sniBody, name...)
	exts = append(exts, ext(0, sniBody)...)
	exts = append(exts, ext(10, []byte{0, 6, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18})...)
	sigalgs := []uint16{0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601}
	sa := binary.BigEndian.AppendUint16(nil, uint16(len(sigalgs)*2))
	for _, s := range sigalgs {
		sa = binary.BigEndian.AppendUint16(sa, s)
	}
	exts = append(exts, ext(13, sa)...)
	exts = append(exts, ext(43, []byte{4, 0x03, 0x04, 0x03, 0x03})...)
	exts = append(exts, ext(45, []byte{1, 0})...)
	share := append([]byte{0x00, 0x1d, 0x00, 0x20}, randBytes(32)...)
	exts = append(exts, ext(51, append([]byte{0, 36}, share...))...)
	exts = append(exts, ext(11, []byte{1, 0})...)
	exts = append(exts, ext(16, []byte{0, 12, 2, 'h', '2', 8, 'h', 't', 't', 'p', '/', '1', '.', '1'})...)
	exts = append(exts, ext(35, nil)...)
	exts = append(exts, ext(0x0a0a, nil)...)

	body = binary.BigEndian.AppendUint16(body, uint16(len(exts)))
	body = append(body, exts...)

	hs := append([]byte{1}, u24(len(body))...)
	hs = append(hs, body...)
	return tlsRecord(tlsHandshake, 0x0301, hs)
}

func buildServerHello() []byte {
	body := []byte{0x03, 0x03}
	body = append(body, randBytes(32)...)
	body = append(body, 0) // no session id
	body = binary.BigEndian.AppendUint16(body, 0x1301)
	body = append(body, 0) // null compression

	var exts []byte
	exts = append(exts, ext(43, []byte{2, 0x03, 0x04})...)
	exts = append(exts, ext(51, append([]byte{0x00, 0x1d, 0x00, 0x20}, randBytes(32)...))...)
	body = binary.BigEndian.AppendUint16(body, uint16(len(exts)))
	body = append(body, exts...)

	hs := append([]byte{2}, u24(len(body))...)
	hs = append(hs, body...)
	return tlsRecord(tlsHandshake, 0x0303, hs)
}

// fakeCertificate is a plausible-looking (but not valid) DER blob. DPIs that
// only look at record structure and lengths are satisfied; a real TLS client
// would reject it, which is out of scope for a camouflage layer.
func fakeCertificate() []byte {
	n := 580 + int(randBytes(1)[0])
	der := make([]byte, 0, n+4)
	der = append(der, 0x30, 0x82, byte(n>>8), byte(n))
	der = append(der, randBytes(n)...)
	return der
}

func buildCertificate() []byte {
	der := fakeCertificate()
	list := u24(len(der) + 3)
	list = append(list, u24(len(der))...)
	list = append(list, der...)
	body := u24(len(list))
	body = append(body, list...)
	hs := append([]byte{11}, u24(len(body))...)
	hs = append(hs, body...)
	return hs
}

func buildCertificateVerify() []byte {
	sig := randBytes(64)
	body := []byte{0x08, 0x04}
	body = binary.BigEndian.AppendUint16(body, uint16(len(sig)))
	body = append(body, sig...)
	hs := append([]byte{15}, u24(len(body))...)
	return append(hs, body...)
}

func buildFinished() []byte {
	body := randBytes(32)
	hs := append([]byte{20}, u24(len(body))...)
	return append(hs, body...)
}

// serverFlight returns the cosmetic server handshake as separate records.
func serverFlight() [][]byte {
	serverHello := buildServerHello()
	ccs := tlsRecord(tlsChangeCipherSpec, 0x0303, []byte{0x01})
	rest := append(buildCertificate(), buildCertificateVerify()...)
	rest = append(rest, buildFinished()...)
	encrypted := tlsRecord(tlsHandshake, 0x0303, rest)
	return [][]byte{serverHello, ccs, encrypted}
}
