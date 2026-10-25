package udp2raw

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

func TestSegmentBuildAndParse(t *testing.T) {
	src := netip.MustParseAddrPort("192.0.2.10:40000")
	dst := netip.MustParseAddrPort("198.51.100.7:443")
	payload := []byte("quic-in-tcp")
	seg := segment{
		Src:     src,
		Dst:     dst,
		Seq:     0x11223344,
		Ack:     0x55667788,
		Flags:   tcpFlagPSH | tcpFlagACK,
		Window:  65535,
		Payload: payload,
	}
	opts := tcpOptions{HasTimestamps: true, TSVal: 1234, TSEcr: 5678}
	pkt, err := buildSegment(seg, opts, 0xabcd, 64)
	if err != nil {
		t.Fatal(err)
	}
	if got := ipv4Checksum(pkt[:ipv4HeaderLen]); got != 0 {
		t.Fatalf("ipv4 checksum does not verify: %#x", got)
	}
	if got := tcpChecksumVerified(pkt); got != 0 {
		t.Fatalf("tcp checksum does not verify: %#x", got)
	}
	if pkt[8] != 64 {
		t.Fatalf("ttl = %d, want 64", pkt[8])
	}

	got, ok := parseSegment(pkt)
	if !ok {
		t.Fatal("parse failed")
	}
	if got.Src != src || got.Dst != dst || got.Seq != seg.Seq || got.Ack != seg.Ack {
		t.Fatalf("header mismatch: %+v", got)
	}
	if got.Flags != seg.Flags || got.Window != seg.Window {
		t.Fatalf("flags/window mismatch: %+v", got)
	}
	if string(got.Payload) != string(payload) {
		t.Fatalf("payload mismatch: %q", got.Payload)
	}
	if !got.TCPOptions.HasTimestamps || got.TCPOptions.TSVal != 1234 || got.TCPOptions.TSEcr != 5678 {
		t.Fatalf("timestamps not parsed: %+v", got.TCPOptions)
	}
}

func TestSYNOptionsMatchLinuxLayout(t *testing.T) {
	opts := buildTCPOptions(tcpOptions{
		HasMSS:         true,
		MSS:            1460,
		HasSackPerm:    true,
		HasTimestamps:  true,
		TSVal:          1,
		TSEcr:          2,
		HasWindowScale: true,
		WindowScale:    7,
	})
	want := []byte{
		2, 4, 0x05, 0xb4, // MSS 1460
		4, 2, // SACK permitted
		8, 10, 0, 0, 0, 1, 0, 0, 0, 2, // timestamps
		1, 3, 3, 7, // NOP, window scale 7
	}
	if string(opts) != string(want) {
		t.Fatalf("option bytes = % x, want % x", opts, want)
	}
	parsed := parseTCPOptions(opts)
	if parsed.MSS != 1460 || parsed.WindowScale != 7 || !parsed.HasSackPerm || !parsed.HasTimestamps {
		t.Fatalf("options did not round trip: %+v", parsed)
	}
}

func TestSACKOptionAlignment(t *testing.T) {
	opts := buildTCPOptions(tcpOptions{
		HasTimestamps: true,
		Sack:          []sackBlock{{Left: 100, Right: 200}, {Left: 300, Right: 400}},
	})
	if len(opts)%4 != 0 {
		t.Fatalf("sack options not padded: %d", len(opts))
	}
	parsed := parseTCPOptions(opts)
	if len(parsed.Sack) != 2 || parsed.Sack[0].Left != 100 || parsed.Sack[1].Right != 400 {
		t.Fatalf("sack blocks not parsed: %+v", parsed.Sack)
	}
}

func TestEthernetAndVLANParsing(t *testing.T) {
	src := netip.MustParseAddrPort("192.0.2.10:40000")
	dst := netip.MustParseAddrPort("198.51.100.7:443")
	pkt, err := buildSegment(segment{Src: src, Dst: dst, Seq: 1, Flags: tcpFlagACK, Window: 100}, tcpOptions{}, 1, 64)
	if err != nil {
		t.Fatal(err)
	}
	eth := make([]byte, 14, 14+len(pkt))
	binary.BigEndian.PutUint16(eth[12:], 0x0800)
	if seg, ok := parseLinkFrame(append(eth, pkt...)); !ok || seg.Src != src {
		t.Fatalf("plain ethernet parse failed: %v", ok)
	}
	vlan := make([]byte, 18, 18+len(pkt))
	binary.BigEndian.PutUint16(vlan[12:], 0x8100)
	binary.BigEndian.PutUint16(vlan[16:], 0x0800)
	if seg, ok := parseLinkFrame(append(vlan, pkt...)); !ok || seg.Src != src {
		t.Fatalf("vlan parse failed: %v", ok)
	}
}

func TestParseSegmentRejectsFragments(t *testing.T) {
	pkt, err := buildSegment(segment{
		Src: netip.MustParseAddrPort("192.0.2.10:1"), Dst: netip.MustParseAddrPort("198.51.100.7:2"),
		Seq: 1, Flags: tcpFlagACK, Window: 1,
	}, tcpOptions{}, 1, 64)
	if err != nil {
		t.Fatal(err)
	}
	pkt[6] |= 0x20 // MF
	if _, ok := parseSegment(pkt); ok {
		t.Fatal("fragment accepted")
	}
}

// tcpChecksumVerified recomputes the TCP checksum over the built packet; a
// correct checksum makes the one's complement sum zero.
func tcpChecksumVerified(pkt []byte) uint16 {
	src := pkt[12:16]
	dst := pkt[16:20]
	tcp := pkt[ipv4HeaderLen:]
	sum := checksumAdd(0, src)
	sum = checksumAdd(sum, dst)
	sum += 6
	sum += uint32(len(tcp))
	sum = checksumAdd(sum, tcp)
	return finishChecksum(sum)
}
