package udp2raw

import (
	crand "crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net/netip"
	"sync"
	"time"
)

var (
	// ErrUnsupported means the current platform has no faketcp backend.
	ErrUnsupported = errors.New("udp2raw: faketcp is not supported on this platform")
	// ErrNoPrivilege means raw sockets were refused by the OS.
	ErrNoPrivilege = errors.New("udp2raw: insufficient privileges for faketcp")
	// ErrHandshake is returned when the peer never completes the handshake.
	ErrHandshake = errors.New("udp2raw: handshake failed")
	// ErrClosed is returned after the connection or session was closed.
	ErrClosed = errors.New("udp2raw: closed")
	// ErrDatagramTooLarge means the datagram does not fit into the configured MTU.
	ErrDatagramTooLarge = errors.New("udp2raw: datagram exceeds mtu")
)

const (
	stateSynSent     int32 = 1
	stateSynRcvd     int32 = 2
	stateHelloSent   int32 = 3
	stateEstablished int32 = 4
	stateClosed      int32 = 5

	ackDelay        = 5 * time.Millisecond
	handshakeRetry  = 1 * time.Second
	pendingDatagram = 8
	recvQueueLen    = 1024
)

// rawEndpoint is one privileged packet path. Implementations are per platform.
type rawEndpoint interface {
	// recv blocks for the next inbound segment whose destination port matches
	// the endpoint filter. The returned payload aliases an internal buffer and
	// is only valid until the next call.
	recv() (segment, error)
	// send emits a complete IPv4 packet.
	send(pkt []byte) error
	close() error
}

type sessionConfig struct {
	auth             string
	keepAlive        time.Duration
	idleTimeout      time.Duration
	handshakeTimeout time.Duration
	dialTimeout      time.Duration
	mss              uint16
	ttl              uint8
	windowScale      uint8
	maxPayload       int
	holeTimeout      time.Duration
	camouflage       string
	sni              string
	replay           *replayCache
}

// session is one fake-TCP flow. All mutable state is guarded by mu; the receive
// loop and the writer both funnel through here.
type session struct {
	client bool
	ep     rawEndpoint
	local  netip.AddrPort
	remote netip.AddrPort
	cfg    sessionConfig
	logf   func(string, ...any)

	// deliver hands one datagram to the owner. It must not block.
	deliver func([]byte)
	// onEstablished is called once, when the handshake completes (server side).
	onEstablished func(*session)
	// onClosed is called once when the session goes away (server side).
	onClosed func(*session)

	mu         sync.Mutex
	state      int32
	closed     bool
	err        error
	sndNxt     uint32
	rcvNxt     uint32
	peerMSS    uint16
	peerTS     uint32
	synSent    bool
	synSeq     uint32
	tsBase     uint32
	started    time.Time
	lastRx     time.Time
	lastTx     time.Time
	ipID       uint16
	ackDue     int
	ackTimer   *time.Timer
	keepTimer  *time.Timer
	hsTimer    *time.Timer
	holeTimer  *time.Timer
	pending    [][]byte
	camo       *camoState
	sack       sackTracker
	helloNonce [8]byte

	txBuf []byte

	done      chan struct{}
	closeOnce sync.Once
}

func newSession(client bool, ep rawEndpoint, local, remote netip.AddrPort, cfg sessionConfig, logf func(string, ...any)) *session {
	s := &session{
		client:  client,
		ep:      ep,
		local:   local,
		remote:  remote,
		cfg:     cfg,
		logf:    logf,
		started: time.Now(),
		lastRx:  time.Now(),
		lastTx:  time.Now(),
		done:    make(chan struct{}),
		txBuf:   make([]byte, 0, cfg.maxPayload+64),
	}
	if cfg.holeTimeout <= 0 {
		cfg.holeTimeout = 150 * time.Millisecond
		s.cfg.holeTimeout = cfg.holeTimeout
	}
	s.sndNxt = randomUint32()
	s.tsBase = randomUint32()
	s.helloNonce = newNonce()
	if cfg.camouflage == CamouflageTLS {
		s.camo = newCamoState(cfg.sni, client)
	}
	return s
}

// startClient kicks off the client handshake.
func (s *session) startClient() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state = stateSynSent
	if err := s.sendSynLocked(tcpFlagSYN); err != nil {
		s.failLocked(err)
		return err
	}
	s.scheduleHandshakeLocked()
	return nil
}

// acceptSyn builds the server-side session state from an incoming SYN.
func (s *session) acceptSyn(seg segment) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state = stateSynRcvd
	s.rcvNxt = seg.Seq + 1
	s.recordPeerOptionsLocked(seg)
	if err := s.sendSynLocked(tcpFlagSYN | tcpFlagACK); err != nil {
		s.failLocked(err)
		return err
	}
	s.scheduleHandshakeLocked()
	return nil
}

func (s *session) scheduleHandshakeLocked() {
	if s.hsTimer != nil {
		s.hsTimer.Stop()
	}
	s.hsTimer = time.AfterFunc(handshakeRetry, s.handshakeTick)
}

func (s *session) handshakeTick() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.state == stateEstablished {
		return
	}
	if time.Since(s.started) >= s.cfg.handshakeTimeout {
		s.failLocked(ErrHandshake)
		return
	}
	switch s.state {
	case stateSynSent:
		_ = s.sendSynLocked(tcpFlagSYN)
	case stateSynRcvd:
		_ = s.sendSynLocked(tcpFlagSYN | tcpFlagACK)
	case stateHelloSent:
		s.sendHelloLocked()
	}
	s.hsTimer = time.AfterFunc(handshakeRetry, s.handshakeTick)
}

// handleSegment processes one inbound segment. Called from the endpoint loop.
func (s *session) handleSegment(seg segment) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	s.lastRx = time.Now()

	if seg.Flags&tcpFlagRST != 0 {
		// Never trust RST: an on-path attacker must not be able to kill a tunnel,
		// and the local kernel may emit one for traffic it does not own.
		return
	}
	if seg.Flags&tcpFlagSYN != 0 {
		if !s.client && s.state == stateSynRcvd {
			// Retransmitted SYN: resend the SYN-ACK with the original ISN.
			_ = s.sendSynLocked(tcpFlagSYN | tcpFlagACK)
		}
		return
	}

	payload := seg.Payload
	if len(payload) > 0 {
		mss := int(s.peerMSS)
		if mss < 536 {
			mss = defaultMSS
		}
		if len(payload) > mss {
			// Linux GRO hands us several coalesced segments at once. Splitting by
			// the peer's advertised MSS recovers the original boundaries.
			seq := seg.Seq
			for off := 0; off < len(payload); off += mss {
				end := off + mss
				if end > len(payload) {
					end = len(payload)
				}
				s.processChunkLocked(seq, payload[off:end])
				seq += uint32(end - off)
			}
		} else {
			s.processChunkLocked(seg.Seq, payload)
		}
	}

	if seg.Flags&tcpFlagFIN != 0 {
		_ = s.sendLocked(tcpFlagFIN|tcpFlagACK, nil, 1)
		s.closeLocked(io.EOF)
		return
	}
	if s.state == stateEstablished {
		s.maybeAckLocked(false)
	}
}

// processChunkLocked handles one (possibly GRO-split) contiguous chunk of TCP
// payload: sequence bookkeeping, duplicate suppression and frame dispatch.
func (s *session) processChunkLocked(seq uint32, payload []byte) {
	diff := int32(seq - s.rcvNxt)
	switch {
	case diff == 0:
		s.rcvNxt += uint32(len(payload))
		// Fold any already-received data that follows the hole into the
		// cumulative ACK. Without this a single loss freezes rcvNxt forever
		// (QUIC never retransmits the same bytes at the same sequence offset),
		// which both breaks duplicate suppression and is a visible DPI tell.
		s.rcvNxt = s.sack.consume(s.rcvNxt)
	case diff < 0:
		overlap := uint32(-diff)
		if overlap >= uint32(len(payload)) {
			// Pure duplicate; the ACK below (or the caller) settles it.
			return
		}
		payload = payload[overlap:]
		seq = s.rcvNxt
		s.rcvNxt += uint32(len(payload))
	default:
		// Ahead of the cumulative point: deliver anyway (QUIC reorders fine)
		// and record the range for SACK.
		s.sack.insert(seq, seq+uint32(len(payload)))
		s.handlePayloadLocked(payload)
		s.armHoleTimerLocked()
		s.maybeAckLocked(true)
		return
	}
	if s.state == stateEstablished {
		s.sack.advance(s.rcvNxt)
	}
	s.handlePayloadLocked(payload)
}

func (s *session) handlePayloadLocked(payload []byte) {
	if s.camo != nil {
		ct, body, ok := splitTLSRecord(payload)
		if !ok {
			return
		}
		send, app := s.camo.ingest(ct, body)
		for _, rec := range send {
			_ = s.sendLocked(tcpFlagPSH|tcpFlagACK, rec, 0)
		}
		if app == nil {
			return
		}
		payload = app
	}
	if s.state == stateEstablished {
		// No framing on the wire for data: the segment payload is exactly the
		// QUIC datagram. That keeps the IP packet identical in size to plain
		// UDP, which matters on paths whose MTU is exactly 1280+40.
		if len(payload) == 0 {
			return
		}
		buf := make([]byte, len(payload))
		copy(buf, payload)
		if s.deliver != nil {
			s.deliver(buf)
		}
		return
	}

	t, data, err := parseFrame(payload)
	if err != nil {
		return
	}
	switch t {
	case frameHello:
		if s.client || s.state != stateSynRcvd {
			return
		}
		s.acceptHelloLocked(data)
	case frameHelloAck:
		if !s.client || s.state != stateHelloSent {
			return
		}
		if len(data) != len(s.helloNonce) || string(data) != string(s.helloNonce[:]) {
			return
		}
		s.establishLocked()
	case frameData:
		// Data frames are only used by the tcp carrier.
	case framePing:
		s.sendFrameLocked(framePong, data)
	case frameClose:
		s.closeLocked(io.EOF)
	}
}

func (s *session) acceptHelloLocked(data []byte) {
	nonce, err := verifyHello(s.cfg.auth, data, time.Now())
	if err != nil {
		if s.logf != nil {
			s.logf("udp2raw: rejecting HELLO from %s: %v", s.remote, err)
		}
		// Stay in SYN_RCVD and let the handshake timer reap us. Not answering is
		// intentional: it gives a scanner no signal.
		return
	}
	if s.cfg.replay != nil && !s.cfg.replay.accept(nonce, time.Now()) {
		return
	}
	s.establishLocked()
	_ = s.sendFrameLockedRaw(frameHelloAck, nonce[:])
}

func (s *session) establishLocked() {
	if s.state == stateEstablished {
		return
	}
	s.state = stateEstablished
	if s.hsTimer != nil {
		s.hsTimer.Stop()
		s.hsTimer = nil
	}
	if s.client {
		for _, d := range s.pending {
			_ = s.sendDatagramLocked(d)
		}
		s.pending = nil
	}
	s.armKeepAliveLocked()
	if s.onEstablished != nil {
		s.onEstablished(s)
	}
}

// sendFrameLocked wraps data in a frame (and TLS record when camouflage is on).
func (s *session) sendFrameLocked(t frameType, data []byte) error {
	return s.sendFrameLockedRaw(t, data)
}

func (s *session) sendFrameLockedRaw(t frameType, data []byte) error {
	buf, err := appendFrame(s.txBuf[:0], t, data, 0)
	if err != nil {
		return err
	}
	payload := buf
	if s.camo != nil {
		payload = s.camo.wrap(buf)
	}
	return s.sendLocked(tcpFlagPSH|tcpFlagACK, payload, 0)
}

// sendDatagram moves one QUIC datagram through the tunnel.
func (s *session) sendDatagram(p []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return s.err
	}
	if s.state != stateEstablished {
		if s.client && len(s.pending) < pendingDatagram {
			cp := make([]byte, len(p))
			copy(cp, p)
			s.pending = append(s.pending, cp)
			return nil
		}
		if s.client {
			return nil
		}
		return ErrHandshake
	}
	return s.sendDatagramLocked(p)
}

func (s *session) sendDatagramLocked(p []byte) error {
	if len(p) > s.datagramLimit() {
		// Drop silently instead of returning an error: quic-go treats a
		// WriteTo error as fatal for the whole connection, while a dropped
		// datagram is just packet loss that its PMTUD/CongestionControl
		// already knows how to react to. This is also what a path MTU black
		// hole looks like on the wire.
		return nil
	}
	payload := p
	if s.camo != nil {
		payload = s.camo.wrap(p)
	}
	return s.sendLocked(tcpFlagPSH|tcpFlagACK, payload, 0)
}

// datagramLimit is the largest datagram we may put in one segment: the
// configured MTU cap, further reduced to the peer's advertised MSS.
func (s *session) datagramLimit() int {
	limit := s.cfg.maxPayload
	if s.peerMSS >= 536 && int(s.peerMSS) < limit {
		limit = int(s.peerMSS)
	}
	return limit
}

// sendLocked renders and emits one segment. advanceSeq is 1 for SYN/FIN.
func (s *session) sendLocked(flags uint8, payload []byte, advanceSeq uint32) error {
	return s.sendWithSeqLocked(flags, payload, s.sndNxt, advanceSeq)
}

// sendSynLocked emits SYN or SYN|ACK. Retransmissions reuse the original ISN,
// like a real TCP stack; advancing it would desynchronise the peer.
func (s *session) sendSynLocked(flags uint8) error {
	if !s.synSent {
		s.synSent = true
		s.synSeq = s.sndNxt
		return s.sendLocked(flags, nil, 1)
	}
	return s.sendWithSeqLocked(flags, nil, s.synSeq, 0)
}

// sendWithSeqLocked is sendLocked with an explicit sequence number.
func (s *session) sendWithSeqLocked(flags uint8, payload []byte, seq, advanceSeq uint32) error {
	if s.closed {
		return s.err
	}
	if len(payload) > s.cfg.maxPayload {
		return nil // same reasoning as sendDatagramLocked
	}
	seg := segment{
		Src:     s.local,
		Dst:     s.remote,
		Seq:     seq,
		Ack:     s.rcvNxt,
		Flags:   flags,
		Window:  65535,
		Payload: payload,
	}
	opts := s.tcpOptionsLocked(flags)
	s.ipID++
	pkt, err := buildSegment(seg, opts, s.ipID, s.cfg.ttl)
	if err != nil {
		return err
	}
	if err := s.ep.send(pkt); err != nil {
		if errors.Is(err, errPacketTooBig) {
			return nil // let QUIC see it as loss
		}
		return err
	}
	s.sndNxt += uint32(len(payload)) + advanceSeq
	s.lastTx = time.Now()
	return nil
}

func (s *session) tcpOptionsLocked(flags uint8) tcpOptions {
	tsVal := s.tsBase + uint32(time.Since(s.started).Milliseconds())
	o := tcpOptions{
		HasTimestamps: true,
		TSVal:         tsVal,
		TSEcr:         s.peerTS,
	}
	if flags&tcpFlagSYN != 0 {
		o.HasMSS = true
		o.MSS = s.cfg.mss
		o.HasSackPerm = true
		o.HasWindowScale = true
		o.WindowScale = s.cfg.windowScale
	}
	if len(s.sack.blocks) > 0 {
		o.Sack = s.sack.top(3)
	}
	return o
}

func (s *session) recordPeerOptionsLocked(seg segment) {
	if seg.TCPOptions.HasMSS {
		s.peerMSS = seg.TCPOptions.MSS
	}
	if seg.TCPOptions.HasTimestamps {
		s.peerTS = seg.TCPOptions.TSVal
	}
}

func (s *session) maybeAckLocked(force bool) {
	if s.state != stateEstablished {
		return
	}
	if !force {
		s.ackDue++
		if s.ackDue < 2 {
			if s.ackTimer == nil {
				s.ackTimer = time.AfterFunc(ackDelay, s.flushAck)
			}
			return
		}
	}
	s.ackDue = 0
	if s.ackTimer != nil {
		s.ackTimer.Stop()
		s.ackTimer = nil
	}
	_ = s.sendLocked(tcpFlagACK, nil, 0)
}

// armHoleTimerLocked schedules the "give up on this hole" timer.
func (s *session) armHoleTimerLocked() {
	if s.holeTimer != nil {
		return
	}
	s.holeTimer = time.AfterFunc(s.cfg.holeTimeout, s.holeTick)
}

// holeTick advances the cumulative ACK past a hole that will never be filled:
// QUIC never retransmits the same bytes at the same sequence offset, so waiting
// for the missing range only freezes the ACK forever (a visible DPI tell and a
// duplicate-suppression hazard).
func (s *session) holeTick() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.holeTimer = nil
	if s.closed || s.state != stateEstablished {
		return
	}
	next, ok := s.sack.nextAbove(s.rcvNxt)
	if !ok {
		return
	}
	s.rcvNxt = s.sack.consume(next)
	_ = s.sendLocked(tcpFlagACK, nil, 0)
}

func (s *session) flushAck() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.state != stateEstablished {
		return
	}
	s.ackDue = 0
	s.ackTimer = nil
	_ = s.sendLocked(tcpFlagACK, nil, 0)
}

func (s *session) armKeepAliveLocked() {
	if s.keepTimer != nil {
		s.keepTimer.Stop()
	}
	s.keepTimer = time.AfterFunc(s.cfg.keepAlive, s.keepAliveTick)
}

func (s *session) keepAliveTick() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.state != stateEstablished {
		return
	}
	if time.Since(s.lastRx) >= s.cfg.idleTimeout {
		s.failLocked(io.ErrNoProgress)
		return
	}
	if time.Since(s.lastTx) >= s.cfg.keepAlive {
		// A bare ACK is what a real TCP stack sends to keep NAT state alive.
		_ = s.sendLocked(tcpFlagACK, nil, 0)
	}
	s.keepTimer = time.AfterFunc(s.cfg.keepAlive, s.keepAliveTick)
}

func (s *session) sendHelloLocked() {
	if s.camo != nil {
		if hello := s.camo.clientHello(); hello != nil {
			_ = s.sendLocked(tcpFlagPSH|tcpFlagACK, hello, 0)
		}
	}
	payload := buildHello(s.cfg.auth, s.helloNonce, time.Now())
	_ = s.sendFrameLockedRaw(frameHello, payload)
}

// onSynAckLocked transitions the client after SYN-ACK.
func (s *session) onSynAckLocked(seg segment) {
	s.rcvNxt = seg.Seq + 1
	s.recordPeerOptionsLocked(seg)
	s.state = stateHelloSent
	s.sendHelloLocked()
}

func (s *session) closeWithError(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closeLocked(err)
}

func (s *session) closeLocked(err error) {
	if s.closed {
		return
	}
	if s.state == stateEstablished && err == nil {
		_ = s.sendLocked(tcpFlagFIN|tcpFlagACK, nil, 1)
	}
	s.closed = true
	s.err = err
	if s.ackTimer != nil {
		s.ackTimer.Stop()
	}
	if s.keepTimer != nil {
		s.keepTimer.Stop()
	}
	if s.hsTimer != nil {
		s.hsTimer.Stop()
	}
	if s.holeTimer != nil {
		s.holeTimer.Stop()
	}
	s.closeOnce.Do(func() {
		close(s.done)
		if s.onClosed != nil {
			s.onClosed(s)
		}
	})
}

func (s *session) failLocked(err error) {
	s.closed = true
	s.err = err
	if s.ackTimer != nil {
		s.ackTimer.Stop()
	}
	if s.keepTimer != nil {
		s.keepTimer.Stop()
	}
	if s.hsTimer != nil {
		s.hsTimer.Stop()
	}
	if s.holeTimer != nil {
		s.holeTimer.Stop()
	}
	s.closeOnce.Do(func() {
		close(s.done)
		if s.onClosed != nil {
			s.onClosed(s)
		}
	})
}

func (s *session) errLocked() error {
	if s.err != nil {
		return s.err
	}
	return ErrClosed
}

func (s *session) Done() <-chan struct{} { return s.done }

// Established reports whether the handshake completed.
func (s *session) Established() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state == stateEstablished
}

// close implements peerConn.
func (s *session) close() error {
	s.closeWithError(nil)
	return nil
}

func (s *session) Error() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.errLocked()
}

// onSegment is the endpoint dispatch entry point for the client side: it detects
// the SYN-ACK that finishes the TCP handshake, everything else is generic.
func (s *session) onSegment(seg segment) {
	s.mu.Lock()
	if !s.closed && s.client && s.state == stateSynSent && seg.Flags&tcpFlagSYN != 0 && seg.Flags&tcpFlagACK != 0 {
		s.onSynAckLocked(seg)
		s.mu.Unlock()
		return
	}
	s.mu.Unlock()
	s.handleSegment(seg)
}

// sackTracker keeps the out-of-order ranges reported in TCP SACK options.
type sackTracker struct {
	blocks []sackBlock
}

func (t *sackTracker) insert(left, right uint32) {
	if left == right {
		return
	}
	for i, b := range t.blocks {
		if left <= b.Right && b.Left <= right {
			if left < b.Left {
				t.blocks[i].Left = left
			}
			if right > b.Right {
				t.blocks[i].Right = right
			}
			t.merge()
			return
		}
	}
	if len(t.blocks) >= 8 {
		// Keep the newest ranges; the older ones will be covered by the
		// cumulative ACK soon enough.
		copy(t.blocks, t.blocks[1:])
		t.blocks = t.blocks[:len(t.blocks)-1]
	}
	t.blocks = append(t.blocks, sackBlock{Left: left, Right: right})
}

func (t *sackTracker) merge() {
	for i := 0; i < len(t.blocks); i++ {
		for j := i + 1; j < len(t.blocks); j++ {
			if t.blocks[i].Left <= t.blocks[j].Right && t.blocks[j].Left <= t.blocks[i].Right {
				if t.blocks[j].Left < t.blocks[i].Left {
					t.blocks[i].Left = t.blocks[j].Left
				}
				if t.blocks[j].Right > t.blocks[i].Right {
					t.blocks[i].Right = t.blocks[j].Right
				}
				t.blocks = append(t.blocks[:j], t.blocks[j+1:]...)
				j--
			}
		}
	}
}

// consume folds SACK ranges that start at or before nxt into the cumulative
// point, returning the new next-expected sequence.
func (t *sackTracker) consume(nxt uint32) uint32 {
	for {
		idx := -1
		for i, b := range t.blocks {
			if int32(b.Left-nxt) <= 0 && int32(nxt-b.Right) < 0 {
				idx = i
				nxt = b.Right
				break
			}
		}
		if idx < 0 {
			return nxt
		}
		t.blocks = append(t.blocks[:idx], t.blocks[idx+1:]...)
	}
}

// nextAbove returns the lowest SACK start strictly above nxt.
func (t *sackTracker) nextAbove(nxt uint32) (uint32, bool) {
	best, found := uint32(0), false
	for _, b := range t.blocks {
		if int32(b.Left-nxt) > 0 && (!found || int32(b.Left-best) < 0) {
			best, found = b.Left, true
		}
	}
	return best, found
}

func (t *sackTracker) advance(nxt uint32) {
	out := t.blocks[:0]
	for _, b := range t.blocks {
		if int32(b.Right-nxt) <= 0 {
			continue
		}
		if int32(b.Left-nxt) < 0 {
			b.Left = nxt
		}
		out = append(out, b)
	}
	t.blocks = out
}

func (t *sackTracker) top(n int) []sackBlock {
	if len(t.blocks) <= n {
		return t.blocks
	}
	return t.blocks[len(t.blocks)-n:]
}

func randomUint32() uint32 {
	var b [4]byte
	if _, err := crand.Read(b[:]); err != nil {
		panic("udp2raw: no randomness available: " + err.Error())
	}
	return binary.BigEndian.Uint32(b[:])
}
