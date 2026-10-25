package udp2raw

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

// tcpCarrier moves frames over a real TCP connection. It works on every
// platform, including those without raw socket support, at the cost of
// TCP-over-TCP head-of-line blocking.
type tcpCarrier struct {
	conn net.Conn
	r    *bufio.Reader
	w    *bufio.Writer
	camo *camoState
	cfg  sessionConfig
	logf func(string, ...any)

	client bool
	local  netip.AddrPort
	remote netip.AddrPort

	writeMu sync.Mutex
	mu      sync.Mutex
	nonce   [8]byte
	pending [][]byte
	est     bool
	closed  atomic.Bool

	deliver       func([]byte)
	onEstablished func()
	onClose       func()
	done          chan struct{}
}

func newTCPCarrier(conn net.Conn, cfg sessionConfig, client bool, logf func(string, ...any)) *tcpCarrier {
	t := &tcpCarrier{
		conn:   conn,
		r:      bufio.NewReaderSize(conn, 64*1024),
		w:      bufio.NewWriterSize(conn, 64*1024),
		cfg:    cfg,
		logf:   logf,
		client: client,
		done:   make(chan struct{}),
	}
	if la, ok := conn.LocalAddr().(*net.TCPAddr); ok {
		t.local = la.AddrPort()
	}
	if ra, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		t.remote = ra.AddrPort()
	}
	if cfg.camouflage == CamouflageTLS {
		t.camo = newCamoState(cfg.sni, client)
	}
	return t
}

func (t *tcpCarrier) start() error {
	t.mu.Lock()
	t.nonce = newNonce()
	t.mu.Unlock()
	if t.client {
		if t.camo != nil {
			if err := t.writeRaw(t.camo.clientHello()); err != nil {
				return err
			}
		}
		return t.writeFrame(frameHello, buildHello(t.cfg.auth, t.nonce, time.Now()))
	}
	return nil
}

func (t *tcpCarrier) sendDatagram(p []byte) error {
	if t.closed.Load() {
		return ErrClosed
	}
	t.mu.Lock()
	established := t.est
	if !established && t.client {
		if len(t.pending) < pendingDatagram {
			t.pending = append(t.pending, append([]byte(nil), p...))
			t.mu.Unlock()
			return nil
		}
		t.mu.Unlock()
		return nil
	}
	t.mu.Unlock()
	if !established {
		return ErrHandshake
	}
	return t.writeFrame(frameData, p)
}

func (t *tcpCarrier) writeFrame(ft frameType, payload []byte) error {
	buf, err := appendFrame(nil, ft, payload, 0)
	if err != nil {
		return err
	}
	if t.camo != nil {
		return t.writeRaw(t.camo.wrap(buf))
	}
	return t.writeRaw(buf)
}

func (t *tcpCarrier) writeRaw(b []byte) error {
	t.writeMu.Lock()
	defer t.writeMu.Unlock()
	if _, err := t.w.Write(b); err != nil {
		return err
	}
	// Flush immediately: buffering would add latency and delay the handshake.
	return t.w.Flush()
}

func (t *tcpCarrier) run() {
	defer t.close()
	for {
		var (
			ft   frameType
			data []byte
			err  error
		)
		if t.camo != nil {
			ft, data, err = t.readCamoFrame()
		} else {
			ft, data, err = t.readPlainFrame()
		}
		if err != nil {
			if !errors.Is(err, io.EOF) && t.logf != nil && !t.closed.Load() {
				t.logf("udp2raw: tcp carrier read error: %v", err)
			}
			return
		}
		t.handleFrame(ft, data)
	}
}

func (t *tcpCarrier) readPlainFrame() (frameType, []byte, error) {
	var hdr [frameHeaderLen]byte
	if _, err := io.ReadFull(t.r, hdr[:]); err != nil {
		return 0, nil, err
	}
	n := int(hdr[0])<<8 | int(hdr[1])
	if n > maxFramePayload {
		return 0, nil, errShortFrame
	}
	payload := make([]byte, n)
	if _, err := io.ReadFull(t.r, payload); err != nil {
		return 0, nil, err
	}
	ft := frameType(hdr[2])
	if ft&^frameKnownMask != 0 {
		return 0, nil, errShortFrame
	}
	return ft, payload, nil
}

func (t *tcpCarrier) readCamoFrame() (frameType, []byte, error) {
	for {
		ct, body, err := readTLSRecord(t.r)
		if err != nil {
			return 0, nil, err
		}
		send, app := t.camo.ingest(ct, body)
		for _, rec := range send {
			if err := t.writeRaw(rec); err != nil {
				return 0, nil, err
			}
		}
		if app == nil {
			continue
		}
		ft, payload, err := parseFrame(app)
		if err != nil {
			return 0, nil, err
		}
		return ft, payload, nil
	}
}

func (t *tcpCarrier) handleFrame(ft frameType, data []byte) {
	switch ft {
	case frameHello:
		if t.client {
			return
		}
		nonce, err := verifyHello(t.cfg.auth, data, time.Now())
		if err != nil {
			if t.logf != nil {
				t.logf("udp2raw: tcp carrier rejecting HELLO from %s: %v", t.remote, err)
			}
			return
		}
		t.mu.Lock()
		already := t.est
		t.est = true
		t.mu.Unlock()
		if !already {
			_ = t.writeFrame(frameHelloAck, nonce[:])
			if t.onEstablished != nil {
				t.onEstablished()
			}
		}
	case frameHelloAck:
		if !t.client {
			return
		}
		if len(data) != len(t.nonce) || string(data) != string(t.nonce[:]) {
			return
		}
		t.mu.Lock()
		t.est = true
		pending := t.pending
		t.pending = nil
		t.mu.Unlock()
		for _, d := range pending {
			_ = t.writeFrame(frameData, d)
		}
		if t.onEstablished != nil {
			t.onEstablished()
		}
	case frameData:
		if len(data) == 0 {
			return
		}
		buf := make([]byte, len(data))
		copy(buf, data)
		if t.deliver != nil {
			t.deliver(buf)
		}
	case framePing:
		_ = t.writeFrame(framePong, data)
	case frameClose:
		t.close()
	}
}

func (t *tcpCarrier) Established() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.est
}

func (t *tcpCarrier) close() error {
	if !t.closed.CompareAndSwap(false, true) {
		return nil
	}
	close(t.done)
	err := t.conn.Close()
	if t.onClose != nil {
		t.onClose()
	}
	return err
}

// dialTCPCarrier opens the client side carrier.
func dialTCPCarrier(ctx context.Context, addr string, cfg sessionConfig, logf func(string, ...any)) (*tcpCarrier, error) {
	d := net.Dialer{Timeout: cfg.dialTimeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
		_ = tc.SetKeepAlive(true)
		_ = tc.SetKeepAlivePeriod(30 * time.Second)
	}
	t := newTCPCarrier(conn, cfg, true, logf)
	if err := t.start(); err != nil {
		_ = t.close()
		return nil, err
	}
	go t.run()
	return t, nil
}
