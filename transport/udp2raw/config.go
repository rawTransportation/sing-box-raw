package udp2raw

import (
	"errors"
	"net"
	"strconv"
	"strings"
	"time"
)

// Carrier modes.
const (
	// ModeAuto prefers faketcp and falls back to tcp when the platform or the
	// process privileges do not allow raw sockets.
	ModeAuto = "auto"
	// ModeFakeTCP crafts TCP segments on the wire without kernel involvement.
	ModeFakeTCP = "faketcp"
	// ModeTCP tunnels datagrams over a real TCP connection.
	ModeTCP = "tcp"
)

// Camouflage modes.
const (
	CamouflageNone = "none"
	CamouflageTLS  = "tls"
)

const (
	defaultMTU              = 1500
	defaultKeepAlive        = 15 * time.Second
	defaultClientIdle       = 45 * time.Second
	defaultServerIdle       = 60 * time.Second
	defaultHandshakeTimeout = 8 * time.Second
	defaultDialTimeout      = 8 * time.Second
	defaultMSS              = 1460
	defaultWindowScale      = 7
	defaultTTL              = 64
	defaultMaxSessions      = 8192
	defaultMaxSessionsPerIP = 256
)

// FakeTCPConfig holds the knobs that only apply to the faketcp carrier.
type FakeTCPConfig struct {
	// SrcPort fixes the client source port; zero picks a free random one.
	SrcPort int
	// TTL is written into the IPv4 header. 64 mimics Linux.
	TTL uint8
	// MSS is advertised in the TCP options and used to split GRO batches.
	MSS uint16
	// WindowScale is advertised in the TCP options.
	WindowScale uint8
	// GROSplit controls splitting of GRO-aggregated captures: "auto", "on", "off".
	GROSplit string
	// RawInterface optionally binds the capture socket to one interface (Linux).
	RawInterface string
}

// TCPConfig holds the knobs that only apply to the tcp carrier.
type TCPConfig struct {
	DialTimeout time.Duration
	Listen      string
}

// ClientConfig configures the client side PacketConn.
type ClientConfig struct {
	// ServerAddr is the logical Hysteria2 endpoint. In faketcp mode its port is
	// the destination TCP port unless Port overrides it.
	ServerAddr *net.UDPAddr
	// Port overrides the carrier TCP port.
	Port int
	Mode string
	Auth string

	MTU              int
	KeepAlive        time.Duration
	IdleTimeout      time.Duration
	HandshakeTimeout time.Duration

	Camouflage string
	SNI        string

	FakeTCP FakeTCPConfig
	TCP     TCPConfig

	// Logger receives diagnostics; nil discards them.
	Logf func(format string, args ...any)
}

// ServerConfig configures the server side PacketConn.
type ServerConfig struct {
	// ListenIP is the address to accept sessions on. A nil or unspecified IP
	// means "any address that reaches this host".
	ListenIP net.IP
	// Port is the carrier TCP port.
	Port int
	Mode string
	Auth string

	MTU              int
	KeepAlive        time.Duration
	IdleTimeout      time.Duration
	HandshakeTimeout time.Duration

	Camouflage string
	SNI        string

	FakeTCP      FakeTCPConfig
	TCP          TCPConfig
	AutoFirewall bool

	MaxSessions      int
	MaxSessionsPerIP int

	Logf func(format string, args ...any)
}

// normalizeMode validates a mode string.
func normalizeMode(mode string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "", ModeAuto:
		return ModeAuto, nil
	case ModeFakeTCP, "fake-tcp", "fake_tcp":
		return ModeFakeTCP, nil
	case ModeTCP:
		return ModeTCP, nil
	default:
		return "", errors.New("udp2raw: unknown mode " + mode)
	}
}

func normalizeCamouflage(c string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(c)) {
	case "", CamouflageNone, "off", "plain":
		return CamouflageNone, nil
	case CamouflageTLS, "tls1.3":
		return CamouflageTLS, nil
	default:
		return "", errors.New("udp2raw: unknown camouflage " + c)
	}
}

func (c *ClientConfig) fill() error {
	var err error
	if c.Mode, err = normalizeMode(c.Mode); err != nil {
		return err
	}
	if c.Camouflage, err = normalizeCamouflage(c.Camouflage); err != nil {
		return err
	}
	if c.ServerAddr == nil {
		return errors.New("udp2raw: server address is required")
	}
	if c.Port == 0 {
		c.Port = c.ServerAddr.Port
	}
	if c.Port <= 0 || c.Port > 65535 {
		return errors.New("udp2raw: invalid carrier port")
	}
	c.fillCommon()
	if c.FakeTCP.SrcPort < 0 || c.FakeTCP.SrcPort > 65535 {
		return errors.New("udp2raw: invalid source port")
	}
	if c.TCP.DialTimeout <= 0 {
		c.TCP.DialTimeout = defaultDialTimeout
	}
	return c.validateCommon()
}

func (c *ServerConfig) fill() error {
	var err error
	if c.Mode, err = normalizeMode(c.Mode); err != nil {
		return err
	}
	if c.Camouflage, err = normalizeCamouflage(c.Camouflage); err != nil {
		return err
	}
	if c.Port <= 0 || c.Port > 65535 {
		return errors.New("udp2raw: invalid carrier port")
	}
	c.fillCommon()
	if c.MaxSessions <= 0 {
		c.MaxSessions = defaultMaxSessions
	}
	if c.MaxSessionsPerIP <= 0 {
		c.MaxSessionsPerIP = defaultMaxSessionsPerIP
	}
	if c.TCP.Listen == "" {
		c.TCP.Listen = net.JoinHostPort("", strconv.Itoa(c.Port))
	}
	return c.validateCommon()
}

func (c *ClientConfig) fillCommon() {
	if c.MTU == 0 {
		c.MTU = defaultMTU
	}
	if c.KeepAlive <= 0 {
		c.KeepAlive = defaultKeepAlive
	}
	if c.IdleTimeout <= 0 {
		c.IdleTimeout = defaultClientIdle
	}
	if c.HandshakeTimeout <= 0 {
		c.HandshakeTimeout = defaultHandshakeTimeout
	}
	fillFakeTCP(&c.FakeTCP, c.MTU)
}

func (c *ServerConfig) fillCommon() {
	if c.MTU == 0 {
		c.MTU = defaultMTU
	}
	if c.KeepAlive <= 0 {
		c.KeepAlive = defaultKeepAlive
	}
	if c.IdleTimeout <= 0 {
		c.IdleTimeout = defaultServerIdle
	}
	if c.HandshakeTimeout <= 0 {
		c.HandshakeTimeout = defaultHandshakeTimeout
	}
	fillFakeTCP(&c.FakeTCP, c.MTU)
}

func fillFakeTCP(f *FakeTCPConfig, mtu int) {
	if f.TTL == 0 {
		f.TTL = defaultTTL
	}
	if f.MSS == 0 {
		if mtu-ipv4HeaderLen-20 >= 536 {
			f.MSS = uint16(mtu - ipv4HeaderLen - 20)
		} else {
			f.MSS = defaultMSS
		}
	}
	if f.WindowScale == 0 {
		f.WindowScale = defaultWindowScale
	}
	if f.GROSplit == "" {
		f.GROSplit = "auto"
	}
}

func (c *ClientConfig) validateCommon() error {
	return validateCommonParams(c.MTU, c.FakeTCP)
}

func (c *ServerConfig) validateCommon() error {
	return validateCommonParams(c.MTU, c.FakeTCP)
}

func validateCommonParams(mtu int, f FakeTCPConfig) error {
	if mtu < 576 || mtu > 9000 {
		return errors.New("udp2raw: mtu must be within 576..9000")
	}
	if int(f.MSS) > mtu-ipv4HeaderLen-20 {
		return errors.New("udp2raw: faketcp mss does not fit into mtu")
	}
	if f.WindowScale > 14 {
		return errors.New("udp2raw: faketcp windowScale must be within 0..14")
	}
	return nil
}

// PrepareClientConfig validates a client configuration and fills in defaults,
// so a bad option fails at configuration time instead of the first dial.
func PrepareClientConfig(cfg ClientConfig) (ClientConfig, error) {
	err := cfg.fill()
	return cfg, err
}

// PrepareServerConfig validates a server configuration and fills in defaults.
func PrepareServerConfig(cfg ServerConfig) (ServerConfig, error) {
	err := cfg.fill()
	return cfg, err
}

// maxWirePayload is the largest datagram the carrier can move: the MTU minus the
// IP+TCP headers minus our frame header.
func (c *ClientConfig) maxWirePayload() int { return c.MTU - ipv4HeaderLen - 20 }

func (c *ServerConfig) maxWirePayload() int { return c.MTU - ipv4HeaderLen - 20 }

// InitialPacketSize returns the QUIC initial packet size that fits into mtu
// once the TCP/IP headers (and the TLS record header, when camouflage is on)
// are subtracted.
//
// It is capped at 1280, the quic-go default: starting any higher would make the
// first packets exceed paths that plain QUIC handles fine (PPPoE, tunnels),
// because DPLPMTUD can only probe upwards from its starting size.
func InitialPacketSize(mtu int, camouflage string) uint16 {
	if mtu <= 0 {
		mtu = defaultMTU
	}
	overhead := ipv4HeaderLen + 20
	if camouflage == CamouflageTLS {
		overhead += 5
	}
	size := mtu - overhead
	if size < 1200 {
		size = 1200
	}
	if size > 1280 {
		size = 1280
	}
	return uint16(size)
}
