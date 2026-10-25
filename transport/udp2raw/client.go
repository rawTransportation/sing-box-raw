package udp2raw

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"
)

// ClientConn is the client-side net.PacketConn. QUIC writes datagrams into it
// exactly as if it were a UDP socket; they come out as TCP-looking segments.
type ClientConn struct {
	cfg  ClientConfig
	logf func(string, ...any)

	serverAddr net.Addr
	server     netip.AddrPort
	local      netip.AddrPort

	peer  peerConn
	sess  *session
	ep    rawEndpoint
	queue *recvQueue

	once   sync.Once
	stopCh chan struct{}
}

// NewClientConn builds the client PacketConn for the configured carrier.
func NewClientConn(cfg ClientConfig) (net.PacketConn, error) {
	if err := cfg.fill(); err != nil {
		return nil, err
	}
	logf := cfg.Logf
	if logf == nil {
		logf = func(string, ...any) {}
	}
	mode := cfg.Mode
	if mode == ModeAuto {
		if faketcpPlatformSupported() {
			mode = ModeFakeTCP
		} else {
			mode = ModeTCP
		}
	}
	switch mode {
	case ModeFakeTCP:
		conn, err := newFakeTCPClient(cfg, logf)
		if err != nil {
			if cfg.Mode == ModeAuto && (errors.Is(err, ErrUnsupported) || errors.Is(err, ErrNoPrivilege)) {
				logf("udp2raw: faketcp unavailable (%v), falling back to tcp carrier", err)
				return newTCPClient(cfg, logf)
			}
			return nil, err
		}
		return conn, nil
	case ModeTCP:
		return newTCPClient(cfg, logf)
	default:
		return nil, fmt.Errorf("udp2raw: unsupported client mode %q", mode)
	}
}

func newTCPClient(cfg ClientConfig, logf func(string, ...any)) (net.PacketConn, error) {
	addr := net.JoinHostPort(cfg.ServerAddr.IP.String(), strconv.Itoa(cfg.Port))
	ctx, cancel := context.WithTimeout(context.Background(), cfg.TCP.DialTimeout)
	defer cancel()
	tc, err := dialTCPCarrier(ctx, addr, clientSessionCfg(cfg), logf)
	if err != nil {
		return nil, fmt.Errorf("udp2raw: dial tcp carrier %s: %w", addr, err)
	}
	c := &ClientConn{
		cfg:        cfg,
		logf:       logf,
		serverAddr: cfg.ServerAddr,
		peer:       tc,
		queue:      newRecvQueue(recvQueueLen),
		stopCh:     make(chan struct{}),
	}
	tc.deliver = func(b []byte) {
		c.queue.push(b, c.serverAddr)
	}
	tc.onClose = func() {
		c.queue.close(net.ErrClosed)
	}
	return c, nil
}

func newFakeTCPClient(cfg ClientConfig, logf func(string, ...any)) (*ClientConn, error) {
	serverIP, ok := netip.AddrFromSlice(cfg.ServerAddr.IP)
	if !ok {
		return nil, errors.New("udp2raw: server address is not a valid IP")
	}
	serverIP = serverIP.Unmap()
	if serverIP.Is6() {
		return nil, errors.New("udp2raw: faketcp currently supports IPv4 only")
	}
	localIP, err := sourceIPFor(serverIP, cfg.Port)
	if err != nil {
		return nil, fmt.Errorf("udp2raw: cannot determine source address: %w", err)
	}
	srcPort := cfg.FakeTCP.SrcPort
	if srcPort == 0 {
		srcPort, err = pickSourcePort(localIP)
		if err != nil {
			return nil, err
		}
	}
	local := netip.AddrPortFrom(localIP, uint16(srcPort))
	remote := netip.AddrPortFrom(serverIP, uint16(cfg.Port))

	ep, err := openRawEndpoint(endpointFilter{
		server:        false,
		serverIP:      serverIP,
		serverPort:    cfg.Port,
		localIP:       localIP,
		localPort:     srcPort,
		interfaceName: cfg.FakeTCP.RawInterface,
		mss:           cfg.FakeTCP.MSS,
		groSplit:      cfg.FakeTCP.GROSplit,
	})
	if err != nil {
		return nil, err
	}

	c := &ClientConn{
		cfg:        cfg,
		logf:       logf,
		serverAddr: cfg.ServerAddr,
		server:     remote,
		local:      local,
		ep:         ep,
		queue:      newRecvQueue(recvQueueLen),
		stopCh:     make(chan struct{}),
	}
	sess := newSession(true, ep, local, remote, clientSessionCfg(cfg), logf)
	sess.deliver = func(b []byte) {
		c.queue.push(b, c.serverAddr)
	}
	c.sess = sess
	c.peer = sess

	if err := sess.startClient(); err != nil {
		_ = ep.close()
		return nil, err
	}
	go c.rawLoop()
	go func() {
		<-sess.Done()
		c.fail(sess.Error())
	}()
	return c, nil
}

func (c *ClientConn) rawLoop() {
	for {
		seg, err := c.ep.recv()
		if err != nil {
			select {
			case <-c.stopCh:
				return
			default:
			}
			c.fail(err)
			return
		}
		if seg.Src != c.server || seg.Dst != c.local {
			continue
		}
		c.sess.onSegment(seg)
	}
}

func (c *ClientConn) fail(err error) {
	c.once.Do(func() {
		if err == nil {
			err = net.ErrClosed
		}
		c.queue.close(err)
		if c.peer != nil {
			_ = c.peer.close()
		}
		if c.ep != nil {
			_ = c.ep.close()
		}
	})
}

// ReadFrom implements net.PacketConn.
func (c *ClientConn) ReadFrom(p []byte) (int, net.Addr, error) {
	return c.queue.pop(p)
}

// WriteTo implements net.PacketConn.
func (c *ClientConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	if err := c.peer.sendDatagram(p); err != nil {
		return 0, err
	}
	return len(p), nil
}

// LocalAddr implements net.PacketConn.
func (c *ClientConn) LocalAddr() net.Addr {
	if c.local.IsValid() {
		return localAddr(c.local.String())
	}
	return localAddr("0.0.0.0:0")
}

// Close implements net.PacketConn.
func (c *ClientConn) Close() error {
	c.once.Do(func() {
		close(c.stopCh)
		if c.peer != nil {
			_ = c.peer.close()
		}
		if c.ep != nil {
			_ = c.ep.close()
		}
		c.queue.close(net.ErrClosed)
	})
	return nil
}

// SetDeadline implements net.PacketConn.
func (c *ClientConn) SetDeadline(t time.Time) error {
	c.queue.setDeadline(t)
	return nil
}

// SetReadDeadline implements net.PacketConn.
func (c *ClientConn) SetReadDeadline(t time.Time) error {
	c.queue.setDeadline(t)
	return nil
}

// SetWriteDeadline implements net.PacketConn.
func (c *ClientConn) SetWriteDeadline(time.Time) error { return nil }

func clientSessionCfg(cfg ClientConfig) sessionConfig {
	return sessionConfig{
		auth:             cfg.Auth,
		keepAlive:        cfg.KeepAlive,
		idleTimeout:      cfg.IdleTimeout,
		handshakeTimeout: cfg.HandshakeTimeout,
		dialTimeout:      cfg.TCP.DialTimeout,
		mss:              cfg.FakeTCP.MSS,
		ttl:              cfg.FakeTCP.TTL,
		windowScale:      cfg.FakeTCP.WindowScale,
		maxPayload:       cfg.maxWirePayload(),
		camouflage:       cfg.Camouflage,
		sni:              cfg.SNI,
	}
}

// sourceIPFor asks the kernel which local address it would route to dst from.
// Connecting a UDP socket sends no packets.
func sourceIPFor(dst netip.Addr, port int) (netip.Addr, error) {
	conn, err := net.DialUDP("udp4", nil, net.UDPAddrFromAddrPort(netip.AddrPortFrom(dst, uint16(port))))
	if err != nil {
		return netip.Addr{}, err
	}
	defer conn.Close()
	la, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		return netip.Addr{}, errors.New("unexpected local address type")
	}
	ip, ok := netip.AddrFromSlice(la.IP)
	if !ok {
		return netip.Addr{}, errors.New("unexpected local address")
	}
	return ip.Unmap(), nil
}

// pickSourcePort finds a port no local socket is listening on. There is an
// unavoidable race between closing the probe socket and using the port, but the
// window is tiny and the consequence is only that some other process gets
// confused, never a security issue.
func pickSourcePort(ip netip.Addr) (int, error) {
	for range 32 {
		port := 20000 + int(randomUint32()%40000)
		ln, err := net.ListenTCP("tcp4", net.TCPAddrFromAddrPort(netip.AddrPortFrom(ip, uint16(port))))
		if err != nil {
			continue
		}
		_ = ln.Close()
		return port, nil
	}
	return 0, errors.New("udp2raw: cannot find a free source port")
}
