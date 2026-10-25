package udp2raw

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestClientHelloLooksLikeTLS(t *testing.T) {
	rec := buildClientHello("example.com")
	ct, body, ok := splitTLSRecord(rec)
	if !ok {
		t.Fatal("not a valid record")
	}
	if ct != tlsHandshake {
		t.Fatalf("content type %#x", ct)
	}
	if body[0] != 1 {
		t.Fatalf("handshake type %d, want ClientHello", body[0])
	}
	declared := int(body[1])<<16 | int(body[2])<<8 | int(body[3])
	if declared != len(body)-4 {
		t.Fatalf("handshake length %d, body %d", declared, len(body)-4)
	}
	if !bytes.Contains(body, []byte("example.com")) {
		t.Fatal("SNI missing from ClientHello")
	}
}

func TestServerFlightIsWellFormed(t *testing.T) {
	flight := serverFlight()
	if len(flight) != 3 {
		t.Fatalf("flight has %d records", len(flight))
	}
	ct, body, ok := splitTLSRecord(flight[0])
	if !ok || ct != tlsHandshake || body[0] != 2 {
		t.Fatalf("first record is not a ServerHello: %v %#x %d", ok, ct, body[0])
	}
	declared := int(body[1])<<16 | int(body[2])<<8 | int(body[3])
	if declared != len(body)-4 {
		t.Fatalf("ServerHello length mismatch")
	}
	ct, body, ok = splitTLSRecord(flight[1])
	if !ok || ct != tlsChangeCipherSpec || len(body) != 1 || body[0] != 1 {
		t.Fatalf("second record is not ChangeCipherSpec")
	}
	ct, body, ok = splitTLSRecord(flight[2])
	if !ok || ct != tlsHandshake || body[0] != 11 {
		t.Fatalf("third record does not start with Certificate")
	}
}

func TestCamoStateMachine(t *testing.T) {
	client := newCamoState("example.com", true)
	server := newCamoState("example.com", false)

	hello := client.clientHello()
	if hello == nil {
		t.Fatal("no ClientHello")
	}
	ct, body, ok := splitTLSRecord(hello)
	if !ok {
		t.Fatal("bad ClientHello record")
	}
	send, app := server.ingest(ct, body)
	if app != nil || len(send) != 3 {
		t.Fatalf("server flight = %d records, app=%v", len(send), app)
	}
	// A retransmitted ClientHello must not trigger a second flight.
	send, _ = server.ingest(ct, body)
	if len(send) != 0 {
		t.Fatal("flight sent twice")
	}

	frame := []byte{0, 3, byte(frameData), 'a', 'b', 'c'}
	rec := client.wrap(frame)
	wrapped := tlsRecord(tlsApplicationData, 0x0303, frame)
	if !bytes.Equal(rec, wrapped) {
		t.Fatal("wrap is not a plain TLS record")
	}
	ct, body, ok = splitTLSRecord(rec)
	if !ok {
		t.Fatal("bad app record")
	}
	_, app = server.ingest(ct, body)
	if !bytes.Equal(app, frame) {
		t.Fatalf("app payload mismatch: %v", app)
	}
}

func TestReadTLSRecord(t *testing.T) {
	rec := tlsRecord(tlsApplicationData, 0x0303, []byte("payload"))
	ct, body, err := readTLSRecord(bytes.NewReader(append(rec, "extra"...)))
	if err != nil {
		t.Fatal(err)
	}
	if ct != tlsApplicationData || string(body) != "payload" {
		t.Fatalf("read back %#x %q", ct, body)
	}
	bad := make([]byte, 5)
	binary.BigEndian.PutUint16(bad[3:], 0xffff)
	if _, _, err := readTLSRecord(bytes.NewReader(bad)); err == nil {
		t.Fatal("oversized record accepted")
	}
}
