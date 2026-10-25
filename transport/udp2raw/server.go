package udp2raw

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"
)

// ServerConn is the server-side net.PacketConn handed to Hysteria's QUIC stack.
// Every remote peer becomes one session; ReadFrom returns the peer as a
// sessionAddr and WriteTo routes back by its string form.
type ServerConn struct {
	cfg  ServerConfig
	logf func(string, ...any)

	ep rawEndpoint
	ln net.Listener

	queue  *recvQueue
	replay *replayCache

	mu          sync.Mutex
	sessions    map[string]*session
	tcpSessions map[string]*tcpCarrier
	closed      bool

	synMu     sync.Mutex
	synWindow map[netip.Addr]*synCounter

	cleanup io.Closer
	stopCh  chan struct{}
	once    sync.Once
}

type synCounter struct {
	count int
	start time.Time
}

const (
	synRatePerSecond = 40
	synWindowCap     = 4096
)

// NewServerConn opens the carrier listener and returns a PacketConn.
func NewServerConn(cfg ServerConfig) (*ServerConn, error) {
	if err := cfg.fill(); err != nil {
		return nil, err
	}
	mode, err := resolveServerMode(cfg.Mode)
	if err != nil {
		return nil, err
	}
	c := &ServerConn{
		cfg:         cfg,
		logf:        cfg.Logf,
		queue:       newRecvQueue(recvQueueLen),
		replay:      newReplayCache(),
		sessions:    make(map[string]*session),
		tcpSessions: make(map[string]*tcpCarrier),
		synWindow:   make(map[netip.Addr]*synCounter),
		stopCh:      make(chan struct{}),
	}
	if c.logf == nil {
		c.logf = func(string, ...any) {}
	}

	switch mode {
	case ModeFakeTCP:
		ep, err := openRawEndpoint(c.endpointFilter())
		if err != nil {
			return nil, err
		}
		c.ep = ep
		if cfg.AutoFirewall {
			cl, fwErr := setupRSTRules(cfg.Port)
			if fwErr != nil {
				c.logf("udp2raw: auto firewall setup failed: %v (add the rules manually, see docs/udp2raw/03-platforms.md)", fwErr)
			} else {
				c.cleanup = cl
			}
		} else if cfg.Port > 0 {
			c.logf("udp2raw: faketcp on port %d requires kernel RST suppression; see docs/udp2raw/03-platforms.md", cfg.Port)
		}
		go c.readRawLoop()
	case ModeTCP:
		ln, err := net.Listen("tcp", cfg.TCP.Listen)
		if err != nil {
			return nil, fmt.Errorf("udp2raw: listen tcp %s: %w", cfg.TCP.Listen, err)
		}
		c.ln = ln
		go c.acceptLoop()
	default:
		return nil, fmt.Errorf("udp2raw: unsupported server mode %q", mode)
	}
	return c, nil
}

func (c *ServerConn) endpointFilter() endpointFilter {
	f := endpointFilter{
		server:        true,
		listenPort:    c.cfg.Port,
		listenIP:      netip.Addr{},
		interfaceName: c.cfg.FakeTCP.RawInterface,
		mss:           c.cfg.FakeTCP.MSS,
		groSplit:      c.cfg.FakeTCP.GROSplit,
	}
	if ip, ok := netip.AddrFromSlice(c.cfg.ListenIP); ok {
		f.listenIP = ip.Unmap()
	}
	return f
}

func (c *ServerConn) sessionCfg() sessionConfig {
	return sessionConfig{
		auth:             c.cfg.Auth,
		keepAlive:        c.cfg.KeepAlive,
		idleTimeout:      c.cfg.IdleTimeout,
		handshakeTimeout: c.cfg.HandshakeTimeout,
		mss:              c.cfg.FakeTCP.MSS,
		ttl:              c.cfg.FakeTCP.TTL,
		windowScale:      c.cfg.FakeTCP.WindowScale,
		maxPayload:       c.cfg.maxWirePayload(),
		camouflage:       c.cfg.Camouflage,
		sni:              c.cfg.SNI,
		replay:           c.replay,
	}
}

func (c *ServerConn) readRawLoop() {
	for {
		seg, err := c.ep.recv()
		if err != nil {
			if !errors.Is(err, net.ErrClosed) {
				c.logf("udp2raw: endpoint read error: %v", err)
			}
			return
		}
		if seg.Dst.Port() != uint16(c.cfg.Port) {
			continue
		}
		sess, created := c.sessionFor(seg)
		if sess == nil || created {
			// A fresh session already consumed the SYN inside acceptSyn;
			// feeding the same segment in again would emit a second SYN-ACK.
			continue
		}
		sess.handleSegment(seg)
	}
}

// sessionFor returns the session for a segment, creating one for a fresh SYN.
// The boolean reports that the segment was fully handled (session created).
func (c *ServerConn) sessionFor(seg segment) (*session, bool) {
	key := seg.Src.String()
	c.mu.Lock()
	sess := c.sessions[key]
	if sess != nil {
		c.mu.Unlock()
		return sess, false
	}
	if c.closed {
		c.mu.Unlock()
		return nil, false
	}
	if seg.Flags&tcpFlagSYN == 0 || seg.Flags&tcpFlagACK != 0 {
		c.mu.Unlock()
		return nil, false
	}
	if len(c.sessions) >= c.cfg.MaxSessions {
		c.mu.Unlock()
		c.logf("udp2raw: session limit reached (%d)", c.cfg.MaxSessions)
		return nil, false
	}
	if !c.allowSyn(seg.Src.Addr()) {
		c.mu.Unlock()
		return nil, false
	}
	sess = newSession(false, c.ep, seg.Dst, seg.Src, c.sessionCfg(), c.logf)
	sess.deliver = func(b []byte) {
		if !c.queue.push(b, addrPortToSessionAddr(seg.Src)) {
			c.logf("udp2raw: receive queue full, dropping datagram from %s", seg.Src)
		}
	}
	sess.onClosed = func(*session) {
		c.mu.Lock()
		delete(c.sessions, key)
		c.mu.Unlock()
	}
	c.sessions[key] = sess
	c.mu.Unlock()

	if err := sess.acceptSyn(seg); err != nil {
		c.logf("udp2raw: cannot accept session from %s: %v", seg.Src, err)
		return nil, false
	}
	return sess, true
}

func (c *ServerConn) allowSyn(ip netip.Addr) bool {
	c.synMu.Lock()
	defer c.synMu.Unlock()
	now := time.Now()
	b := c.synWindow[ip]
	if b == nil || now.Sub(b.start) > time.Second {
		b = &synCounter{start: now}
		c.synWindow[ip] = b
	}
	b.count++
	if len(c.synWindow) > synWindowCap {
		cutoff := now.Add(-10 * time.Second)
		for k, v := range c.synWindow {
			if v.start.Before(cutoff) {
				delete(c.synWindow, k)
			}
		}
	}
	return b.count <= synRatePerSecond
}

func (c *ServerConn) acceptLoop() {
	for {
		conn, err := c.ln.Accept()
		if err != nil {
			select {
			case <-c.stopCh:
				return
			default:
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			c.logf("udp2raw: accept error: %v", err)
			return
		}
		key := conn.RemoteAddr().String()
		tc := newTCPCarrier(conn, c.sessionCfg(), false, c.logf)
		c.mu.Lock()
		if c.closed || len(c.tcpSessions) >= c.cfg.MaxSessions {
			c.mu.Unlock()
			_ = conn.Close()
			continue
		}
		c.tcpSessions[key] = tc
		c.mu.Unlock()
		tc.deliver = func(b []byte) {
			if !c.queue.push(b, sessionAddr(key)) {
				c.logf("udp2raw: receive queue full, dropping datagram from %s", key)
			}
		}
		tc.onClose = func() {
			c.mu.Lock()
			delete(c.tcpSessions, key)
			c.mu.Unlock()
		}
		if err := tc.start(); err != nil {
			_ = tc.close()
			continue
		}
		go tc.run()
	}
}

// ReadFrom implements net.PacketConn.
func (c *ServerConn) ReadFrom(p []byte) (int, net.Addr, error) {
	return c.queue.pop(p)
}

// WriteTo implements net.PacketConn.
func (c *ServerConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	key := addr.String()
	c.mu.Lock()
	sess := c.sessions[key]
	tc := c.tcpSessions[key]
	c.mu.Unlock()
	if sess != nil {
		if err := sess.sendDatagram(p); err != nil {
			return 0, err
		}
		return len(p), nil
	}
	if tc != nil {
		if err := tc.sendDatagram(p); err != nil {
			return 0, err
		}
		return len(p), nil
	}
	return 0, fmt.Errorf("udp2raw: unknown session %s", key)
}

// LocalAddr implements net.PacketConn.
func (c *ServerConn) LocalAddr() net.Addr {
	ip := "0.0.0.0"
	if c.cfg.ListenIP != nil && !c.cfg.ListenIP.IsUnspecified() {
		ip = c.cfg.ListenIP.String()
	}
	return localAddr(net.JoinHostPort(ip, strconv.Itoa(c.cfg.Port)))
}

// Close implements net.PacketConn.
func (c *ServerConn) Close() error {
	c.once.Do(func() {
		close(c.stopCh)
		c.mu.Lock()
		c.closed = true
		sessions := make([]*session, 0, len(c.sessions))
		for _, s := range c.sessions {
			sessions = append(sessions, s)
		}
		carriers := make([]*tcpCarrier, 0, len(c.tcpSessions))
		for _, tc := range c.tcpSessions {
			carriers = append(carriers, tc)
		}
		c.mu.Unlock()

		for _, s := range sessions {
			s.closeWithError(nil)
		}
		for _, tc := range carriers {
			_ = tc.close()
		}
		if c.ln != nil {
			_ = c.ln.Close()
		}
		if c.ep != nil {
			_ = c.ep.close()
		}
		if c.cleanup != nil {
			_ = c.cleanup.Close()
		}
		c.queue.close(net.ErrClosed)
	})
	return nil
}

// SetDeadline implements net.PacketConn.
func (c *ServerConn) SetDeadline(t time.Time) error {
	c.queue.setDeadline(t)
	return nil
}

// SetReadDeadline implements net.PacketConn.
func (c *ServerConn) SetReadDeadline(t time.Time) error {
	c.queue.setDeadline(t)
	return nil
}

// SetWriteDeadline implements net.PacketConn. Writes are synchronous, so this
// only exists for interface completeness.
func (c *ServerConn) SetWriteDeadline(time.Time) error { return nil }
