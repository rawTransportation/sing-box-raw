package hysteria2

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/udp2raw"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// udp2rawDialer substitutes the QUIC transport socket with a carrier that looks
// like a TCP flow. Hysteria2 dials its QUIC socket through the dialer, so the
// rest of the client (authentication, streams, datagrams) is unchanged.
type udp2rawDialer struct {
	N.Dialer
	template udp2raw.ClientConfig
}

func newUDP2RawClientConfig(options *option.Hysteria2UDP2RawOptions, serverName string, logf func(string, ...any)) udp2raw.ClientConfig {
	config := udp2raw.ClientConfig{
		Mode:             options.Mode,
		Port:             int(options.Port),
		Auth:             options.Auth,
		MTU:              options.MTU,
		KeepAlive:        time.Duration(options.KeepAlive),
		IdleTimeout:      time.Duration(options.IdleTimeout),
		HandshakeTimeout: time.Duration(options.HandshakeTimeout),
		Camouflage:       options.Camouflage,
		SNI:              options.SNI,
		FakeTCP: udp2raw.FakeTCPConfig{
			SrcPort:      int(options.FakeTCP.SrcPort),
			TTL:          options.FakeTCP.TTL,
			MSS:          options.FakeTCP.MSS,
			WindowScale:  options.FakeTCP.WindowScale,
			GROSplit:     options.FakeTCP.GROSplit,
			RawInterface: options.FakeTCP.RawInterface,
		},
		TCP:  udp2raw.TCPConfig{DialTimeout: time.Duration(options.TCP.DialTimeout)},
		Logf: logf,
	}
	if config.SNI == "" && options.Camouflage == udp2raw.CamouflageTLS {
		config.SNI = serverName
	}
	return config
}

func newUDP2RawDialer(dialer N.Dialer, logger logger.Logger, serverName string, options *option.Hysteria2UDP2RawOptions) *udp2rawDialer {
	return &udp2rawDialer{
		Dialer: dialer,
		template: newUDP2RawClientConfig(options, serverName, func(format string, args ...any) {
			logger.Debug(fmt.Sprintf(format, args...))
		}),
	}
}

func (d *udp2rawDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if N.NetworkName(network) != N.NetworkUDP {
		return d.Dialer.DialContext(ctx, network, destination)
	}
	serverAddr, err := d.resolveServerAddr(ctx, destination)
	if err != nil {
		return nil, err
	}
	config := d.template
	config.ServerAddr = serverAddr
	if config.Mode == udp2raw.ModeAuto && serverAddr.IP.To4() == nil {
		// faketcp is IPv4 only; auto silently prefers the carrier that works.
		config.Mode = udp2raw.ModeTCP
	}
	packetConn, err := udp2raw.NewClientConn(config)
	if err != nil {
		return nil, E.Cause(err, "create udp2raw connection to ", M.SocksaddrFromNet(serverAddr))
	}
	return bufio.NewBindPacketConn(packetConn, M.SocksaddrFromNet(serverAddr)), nil
}

// resolveServerAddr turns a domain server address into the IP the carrier will
// use. A plain UDP dial performs the same resolution, routing and interface
// binding the regular hysteria2 socket would have used, without sending packets.
func (d *udp2rawDialer) resolveServerAddr(ctx context.Context, destination M.Socksaddr) (*net.UDPAddr, error) {
	if destination.IsIP() {
		return destination.UDPAddr(), nil
	}
	probe, err := d.Dialer.DialContext(ctx, N.NetworkUDP, destination)
	if err != nil {
		return nil, E.Cause(err, "resolve udp2raw server address")
	}
	remoteAddr := probe.RemoteAddr()
	_ = probe.Close()
	udpAddr, isUDPAddr := remoteAddr.(*net.UDPAddr)
	if !isUDPAddr || udpAddr.IP == nil {
		return nil, E.New("udp2raw: unexpected resolved address: ", remoteAddr)
	}
	return udpAddr, nil
}

func udp2rawListenAddress(options option.ListenOptions, carrierPort int) M.Socksaddr {
	listenAddr := netip.AddrFrom4([4]byte{127, 0, 0, 1})
	if options.Listen != nil {
		listenAddr = options.Listen.Build(listenAddr)
	}
	return M.SocksaddrFrom(listenAddr, uint16(carrierPort))
}

func newUDP2RawServerConfig(options *option.Hysteria2UDP2RawInboundOptions, listenOptions option.ListenOptions, logf func(string, ...any)) (udp2raw.ServerConfig, error) {
	carrierPort := int(options.Port)
	if carrierPort == 0 {
		carrierPort = int(listenOptions.ListenPort)
	}
	if carrierPort == 0 {
		return udp2raw.ServerConfig{}, E.New("udp2raw: missing carrier port, set udp2raw.port")
	}
	config := udp2raw.ServerConfig{
		Port:             carrierPort,
		Mode:             options.Mode,
		Auth:             options.Auth,
		MTU:              options.MTU,
		KeepAlive:        time.Duration(options.KeepAlive),
		IdleTimeout:      time.Duration(options.IdleTimeout),
		HandshakeTimeout: time.Duration(options.HandshakeTimeout),
		Camouflage:       options.Camouflage,
		SNI:              options.SNI,
		FakeTCP: udp2raw.FakeTCPConfig{
			SrcPort:      int(options.FakeTCP.SrcPort),
			TTL:          options.FakeTCP.TTL,
			MSS:          options.FakeTCP.MSS,
			WindowScale:  options.FakeTCP.WindowScale,
			GROSplit:     options.FakeTCP.GROSplit,
			RawInterface: options.FakeTCP.RawInterface,
		},
		TCP:              udp2raw.TCPConfig{Listen: options.TCP.Listen},
		AutoFirewall:     options.AutoFirewall,
		MaxSessions:      options.MaxSessions,
		MaxSessionsPerIP: options.MaxSessionsPerIP,
		Logf:             logf,
	}
	if listenOptions.Listen != nil {
		listenAddr := listenOptions.Listen.Build(netip.IPv4Unspecified())
		if !listenAddr.IsUnspecified() {
			config.ListenIP = net.IP(listenAddr.AsSlice())
		}
	}
	return udp2raw.PrepareServerConfig(config)
}

// udp2rawInitialPacketSize keeps the first QUIC packets inside the carrier MTU.
func udp2rawInitialPacketSize(options *option.Hysteria2UDP2RawOptions) int {
	return int(udp2raw.InitialPacketSize(options.MTU, options.Camouflage))
}
