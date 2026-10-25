package udp2raw

import (
	"bytes"
	"net/netip"
	"sync"
	"testing"
	"time"
)

func TestHandshakeAndBidirectionalData(t *testing.T) {
	epC, epS := newMemPair()
	defer epC.close()
	defer epS.close()

	cAddr := mustAddr(t, "192.0.2.1:40000")
	sAddr := mustAddr(t, "198.51.100.1:443")
	cfg := testSessionCfg()

	clientData := make(chan []byte, 8)
	serverData := make(chan []byte, 8)

	cs := newSession(true, epC, cAddr, sAddr, cfg, t.Logf)
	cs.deliver = func(b []byte) { clientData <- b }
	ss := newSession(false, epS, sAddr, cAddr, cfg, t.Logf)
	ss.deliver = func(b []byte) { serverData <- b }

	pump(t, epC, cs.onSegment)
	pump(t, epS, func(seg segment) {
		if seg.Flags&tcpFlagSYN != 0 && seg.Flags&tcpFlagACK == 0 {
			if err := ss.acceptSyn(seg); err != nil {
				t.Logf("acceptSyn: %v", err)
			}
			return
		}
		ss.handleSegment(seg)
	})

	if err := cs.startClient(); err != nil {
		t.Fatal(err)
	}
	waitEstablished(t, cs)
	waitEstablished(t, ss)

	if err := cs.sendDatagram([]byte("hello quic")); err != nil {
		t.Fatal(err)
	}
	if got := waitFor(t, serverData, time.Second); string(got) != "hello quic" {
		t.Fatalf("server got %q", got)
	}

	if err := ss.sendDatagram([]byte("pong")); err != nil {
		t.Fatal(err)
	}
	if got := waitFor(t, clientData, time.Second); string(got) != "pong" {
		t.Fatalf("client got %q", got)
	}
}

func TestDuplicateIsDeliveredOnce(t *testing.T) {
	epC, epS := newMemPair()
	defer epC.close()
	defer epS.close()

	cs, ss, serverData := handshake(t, epC, epS)

	var last []byte
	epC.setHook(func(pkt []byte) bool {
		if seg, ok := parseSegment(pkt); ok && len(seg.Payload) > 0 {
			last = append([]byte(nil), pkt...)
		}
		return true
	})
	if err := cs.sendDatagram([]byte("once")); err != nil {
		t.Fatal(err)
	}
	if got := waitFor(t, serverData, time.Second); string(got) != "once" {
		t.Fatalf("got %q", got)
	}
	if last == nil {
		t.Fatal("no captured packet")
	}
	epS.push(last)
	select {
	case b := <-serverData:
		t.Fatalf("duplicate delivered: %q", b)
	case <-time.After(150 * time.Millisecond):
	}
	_ = ss
}

func TestReorderingIsTolerated(t *testing.T) {
	epC, epS := newMemPair()
	defer epC.close()
	defer epS.close()

	cs, _, serverData := handshake(t, epC, epS)
	epC.setReorder(true)
	if err := cs.sendDatagram([]byte("first")); err != nil {
		t.Fatal(err)
	}
	if err := cs.sendDatagram([]byte("second")); err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for range 2 {
		got[string(waitFor(t, serverData, time.Second))] = true
	}
	if !got["first"] || !got["second"] {
		t.Fatalf("missing datagrams: %v", got)
	}
}

func TestDatagramTooLargeIsDropped(t *testing.T) {
	epC, epS := newMemPair()
	defer epC.close()
	defer epS.close()
	cs, _, serverData := handshake(t, epC, epS)
	big := bytes.Repeat([]byte("x"), 2000)
	// Silently dropped: a WriteTo error would be fatal for the QUIC connection.
	if err := cs.sendDatagram(big); err != nil {
		t.Fatalf("oversized datagram must not error: %v", err)
	}
	select {
	case got := <-serverData:
		t.Fatalf("oversized datagram delivered: %d bytes", len(got))
	case <-time.After(100 * time.Millisecond):
	}
}

func TestClientQueuesBeforeEstablished(t *testing.T) {
	epC, epS := newMemPair()
	defer epC.close()
	defer epS.close()
	cAddr := mustAddr(t, "192.0.2.1:40000")
	sAddr := mustAddr(t, "198.51.100.1:443")
	cfg := testSessionCfg()
	cs := newSession(true, epC, cAddr, sAddr, cfg, t.Logf)
	serverData := make(chan []byte, 8)
	ss := newSession(false, epS, sAddr, cAddr, cfg, t.Logf)
	ss.deliver = func(b []byte) { serverData <- b }

	// Queue before any handshake happened.
	if err := cs.sendDatagram([]byte("early")); err != nil {
		t.Fatal(err)
	}
	pump(t, epC, cs.onSegment)
	pump(t, epS, func(seg segment) {
		if seg.Flags&tcpFlagSYN != 0 && seg.Flags&tcpFlagACK == 0 {
			_ = ss.acceptSyn(seg)
			return
		}
		ss.handleSegment(seg)
	})
	if err := cs.startClient(); err != nil {
		t.Fatal(err)
	}
	if got := waitFor(t, serverData, 2*time.Second); string(got) != "early" {
		t.Fatalf("queued datagram not flushed: %q", got)
	}
}

func TestHandshakeTimeout(t *testing.T) {
	epC, _ := newMemPair()
	defer epC.close()
	cfg := testSessionCfg()
	cfg.handshakeTimeout = 150 * time.Millisecond
	cs := newSession(true, epC, mustAddr(t, "192.0.2.1:40000"), mustAddr(t, "198.51.100.1:443"), cfg, t.Logf)
	if err := cs.startClient(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-cs.Done():
		if cs.Error() != ErrHandshake {
			t.Fatalf("unexpected error: %v", cs.Error())
		}
	case <-time.After(3 * time.Second):
		t.Fatal("handshake timeout never fired")
	}
}

func TestHelloAuthRejectedWithWrongSecret(t *testing.T) {
	epC, epS := newMemPair()
	defer epC.close()
	defer epS.close()
	cAddr := mustAddr(t, "192.0.2.1:40000")
	sAddr := mustAddr(t, "198.51.100.1:443")

	cCfg := testSessionCfg()
	cCfg.auth = "client-secret"
	sCfg := testSessionCfg()
	sCfg.auth = "server-secret"

	cs := newSession(true, epC, cAddr, sAddr, cCfg, t.Logf)
	ss := newSession(false, epS, sAddr, cAddr, sCfg, t.Logf)
	pump(t, epC, cs.onSegment)
	pump(t, epS, func(seg segment) {
		if seg.Flags&tcpFlagSYN != 0 && seg.Flags&tcpFlagACK == 0 {
			_ = ss.acceptSyn(seg)
			return
		}
		ss.handleSegment(seg)
	})
	if err := cs.startClient(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-cs.Done():
	case <-time.After(3 * time.Second):
		t.Fatal("mismatched auth did not fail the client")
	}
	if ss.Established() {
		t.Fatal("server accepted a bad HELLO")
	}
}

func handshake(t *testing.T, epC, epS *memEndpoint) (*session, *session, chan []byte) {
	t.Helper()
	cAddr := mustAddr(t, "192.0.2.1:40000")
	sAddr := mustAddr(t, "198.51.100.1:443")
	cfg := testSessionCfg()
	clientData := make(chan []byte, 32)
	serverData := make(chan []byte, 32)
	cs := newSession(true, epC, cAddr, sAddr, cfg, t.Logf)
	cs.deliver = func(b []byte) { clientData <- b }
	ss := newSession(false, epS, sAddr, cAddr, cfg, t.Logf)
	ss.deliver = func(b []byte) { serverData <- b }
	pump(t, epC, cs.onSegment)
	pump(t, epS, func(seg segment) {
		if seg.Flags&tcpFlagSYN != 0 && seg.Flags&tcpFlagACK == 0 {
			_ = ss.acceptSyn(seg)
			return
		}
		ss.handleSegment(seg)
	})
	if err := cs.startClient(); err != nil {
		t.Fatal(err)
	}
	waitEstablished(t, cs)
	waitEstablished(t, ss)
	return cs, ss, serverData
}

func waitEstablished(t *testing.T, s *session) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if s.Established() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatal("session did not establish")
}

func TestSYNRetransmitKeepsISN(t *testing.T) {
	epC, _ := newMemPair()
	defer epC.close()

	var mu sync.Mutex
	var synSeqs []uint32
	epC.setHook(func(pkt []byte) bool {
		if seg, ok := parseSegment(pkt); ok && seg.Flags&tcpFlagSYN != 0 && seg.Flags&tcpFlagACK == 0 {
			mu.Lock()
			synSeqs = append(synSeqs, seg.Seq)
			mu.Unlock()
		}
		return true
	})
	cfg := testSessionCfg()
	cs := newSession(true, epC, mustAddr(t, "192.0.2.1:40000"), mustAddr(t, "198.51.100.1:443"), cfg, nil)
	if err := cs.startClient(); err != nil {
		t.Fatal(err)
	}
	cs.handshakeTick() // force one retransmission
	time.Sleep(50 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	if len(synSeqs) < 2 {
		t.Fatalf("expected at least 2 SYNs, got %d", len(synSeqs))
	}
	if synSeqs[0] != synSeqs[1] {
		t.Fatalf("SYN retransmission changed the ISN: %d vs %d", synSeqs[0], synSeqs[1])
	}
}

func TestServerSendsOneSynAckPerSyn(t *testing.T) {
	epC, epS := newMemPair()
	defer epC.close()
	defer epS.close()

	var mu sync.Mutex
	var synAcks []segment
	// The SYN-ACK is emitted by the server endpoint.
	epS.setHook(func(pkt []byte) bool {
		if seg, ok := parseSegment(pkt); ok && seg.Flags&tcpFlagSYN != 0 && seg.Flags&tcpFlagACK != 0 {
			mu.Lock()
			synAcks = append(synAcks, seg)
			mu.Unlock()
		}
		return true
	})

	cfg := ServerConfig{Port: 443, Mode: ModeFakeTCP}
	if err := cfg.fill(); err != nil {
		t.Fatal(err)
	}
	c := &ServerConn{
		cfg:         cfg,
		logf:        t.Logf,
		queue:       newRecvQueue(8),
		replay:      newReplayCache(),
		sessions:    make(map[string]*session),
		tcpSessions: make(map[string]*tcpCarrier),
		synWindow:   make(map[netip.Addr]*synCounter),
		stopCh:      make(chan struct{}),
	}
	c.ep = epS
	go c.readRawLoop()

	syn := segment{
		Src:    mustAddr(t, "192.0.2.1:40000"),
		Dst:    mustAddr(t, "198.51.100.1:443"),
		Seq:    12345,
		Flags:  tcpFlagSYN,
		Window: 65535,
	}
	pkt, err := buildSegment(syn, tcpOptions{
		HasMSS: true, MSS: 1460, HasSackPerm: true,
		HasTimestamps: true, HasWindowScale: true, WindowScale: 7,
	}, 1, 64)
	if err != nil {
		t.Fatal(err)
	}
	if err := epC.send(pkt); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	if err := epC.send(pkt); err != nil { // retransmitted SYN
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	if len(synAcks) != 2 {
		t.Fatalf("expected 2 SYN-ACKs (one per SYN), got %d", len(synAcks))
	}
	if synAcks[0].Seq != synAcks[1].Seq {
		t.Fatalf("SYN-ACK retransmission changed the ISN: %d vs %d", synAcks[0].Seq, synAcks[1].Seq)
	}
}

func TestFakeTCPDataIsUnframed(t *testing.T) {
	epC, epS := newMemPair()
	defer epC.close()
	defer epS.close()

	cs, _, serverData := handshake(t, epC, epS)

	var mu sync.Mutex
	var payloads [][]byte
	epC.setHook(func(pkt []byte) bool {
		if seg, ok := parseSegment(pkt); ok && len(seg.Payload) > 0 {
			mu.Lock()
			payloads = append(payloads, append([]byte(nil), seg.Payload...))
			mu.Unlock()
		}
		return true
	})
	dg := []byte("raw-datagram-without-frame-header")
	if err := cs.sendDatagram(dg); err != nil {
		t.Fatal(err)
	}
	if got := waitFor(t, serverData, time.Second); string(got) != string(dg) {
		t.Fatalf("server got %q", got)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(payloads) == 0 {
		t.Fatal("no captured segment")
	}
	last := payloads[len(payloads)-1]
	if !bytes.Equal(last, dg) {
		t.Fatalf("segment payload is framed: % x", last)
	}
}

func TestDatagramLimitedByPeerMSS(t *testing.T) {
	epC, epS := newMemPair()
	defer epC.close()
	defer epS.close()
	cs, ss, _ := handshake(t, epC, epS)
	_ = cs

	ss.mu.Lock()
	ss.peerMSS = 600
	ss.mu.Unlock()
	if err := ss.sendDatagram(make([]byte, 700)); err != nil {
		t.Fatalf("oversized datagram must be dropped silently, got %v", err)
	}
	if err := ss.sendDatagram(make([]byte, 600)); err != nil {
		t.Fatalf("datagram at the MSS limit rejected: %v", err)
	}
}

func TestInitialPacketSize(t *testing.T) {
	cases := []struct {
		mtu    int
		camo   string
		expect uint16
	}{
		{1500, CamouflageNone, 1280},
		{1320, CamouflageNone, 1280},
		{1320, CamouflageTLS, 1275},
		{1300, CamouflageNone, 1260},
		{600, CamouflageNone, 1200},
	}
	for _, c := range cases {
		if got := InitialPacketSize(c.mtu, c.camo); got != c.expect {
			t.Fatalf("InitialPacketSize(%d, %q) = %d, want %d", c.mtu, c.camo, got, c.expect)
		}
	}
}

func TestSACKHoleIsConsumedAfterFill(t *testing.T) {
	ep, _ := newMemPair()
	defer ep.close()
	cfg := testSessionCfg()
	s := newSession(false, ep, mustAddr(t, "198.51.100.1:443"), mustAddr(t, "192.0.2.1:40000"), cfg, nil)
	s.state = stateEstablished
	s.rcvNxt = 100

	// Data after the hole arrives first: it is delivered and SACKed.
	s.processChunkLocked(200, make([]byte, 50))
	if s.rcvNxt != 100 {
		t.Fatalf("cumulative point moved before the hole was filled: %d", s.rcvNxt)
	}
	// The hole filler arrives: the cumulative point must jump over the SACKed range.
	s.processChunkLocked(100, make([]byte, 100))
	if s.rcvNxt != 250 {
		t.Fatalf("SACK range not folded into rcvNxt: got %d, want 250", s.rcvNxt)
	}
	if len(s.sack.blocks) != 0 {
		t.Fatalf("SACK blocks not consumed: %+v", s.sack.blocks)
	}
}

func TestHoleTimeoutAdvancesAck(t *testing.T) {
	ep, _ := newMemPair()
	defer ep.close()
	cfg := testSessionCfg()
	cfg.holeTimeout = 20 * time.Millisecond
	s := newSession(false, ep, mustAddr(t, "198.51.100.1:443"), mustAddr(t, "192.0.2.1:40000"), cfg, nil)
	s.state = stateEstablished
	s.rcvNxt = 100

	s.mu.Lock()
	s.processChunkLocked(200, make([]byte, 50)) // hole 100..200 never filled
	s.mu.Unlock()

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		s.mu.Lock()
		got := s.rcvNxt
		s.mu.Unlock()
		if got == 250 {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("cumulative ACK never advanced past the un-fillable hole")
}

func TestServerFlightStartsWithServerHello(t *testing.T) {
	epC, epS := newMemPair()
	defer epC.close()
	defer epS.close()
	cfg := testSessionCfg()
	cfg.camouflage = CamouflageTLS

	var mu sync.Mutex
	var sent [][]byte
	epS.setHook(func(pkt []byte) bool {
		if seg, ok := parseSegment(pkt); ok && len(seg.Payload) > 0 {
			mu.Lock()
			sent = append(sent, append([]byte(nil), seg.Payload...))
			mu.Unlock()
		}
		return true
	})

	sAddr := mustAddr(t, "198.51.100.1:443")
	ss := newSession(false, epS, sAddr, mustAddr(t, "192.0.2.1:40000"), cfg, nil)
	syn := segment{Src: mustAddr(t, "192.0.2.1:40000"), Dst: sAddr, Seq: 7, Flags: tcpFlagSYN, Window: 65535}
	syn.TCPOptions = tcpOptions{HasMSS: true, MSS: 1460}
	if err := ss.acceptSyn(syn); err != nil {
		t.Fatal(err)
	}

	cli := newCamoState("example.com", true)
	ss.mu.Lock()
	ss.handlePayloadLocked(cli.clientHello())
	ss.mu.Unlock()

	mu.Lock()
	defer mu.Unlock()
	if len(sent) < 3 {
		t.Fatalf("expected 3 handshake records, got %d", len(sent))
	}
	ct, body, ok := splitTLSRecord(sent[0])
	if !ok || ct != tlsHandshake || body[0] != 2 {
		t.Fatalf("first record is not ServerHello: ok=%v ct=%#x type=%d", ok, ct, body[0])
	}
}
