package udp2raw

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
)

const ethernetHeaderLen = 14

// endpointFilter describes what a raw endpoint should capture.
type endpointFilter struct {
	server bool

	// client side
	serverIP   netip.Addr
	serverPort int
	localIP    netip.Addr
	localPort  int

	// server side
	listenPort int
	listenIP   netip.Addr // invalid or unspecified means "any local address"

	interfaceName string
	mss           uint16
	groSplit      string
}

// resolveServerMode turns "auto" into a concrete mode for the server.
func resolveServerMode(mode string) (string, error) {
	switch mode {
	case ModeAuto:
		if faketcpPlatformSupported() {
			return ModeFakeTCP, nil
		}
		return ModeTCP, nil
	case ModeFakeTCP, ModeTCP:
		return mode, nil
	default:
		return "", fmt.Errorf("udp2raw: unsupported server mode %q", mode)
	}
}

// errPacketTooBig reports a datagram the interface MTU cannot carry. The
// session turns it into silent loss so QUIC can adapt instead of dying.
var errPacketTooBig = errors.New("udp2raw: packet exceeds interface mtu")

// mapSockErr normalizes permission errors so callers can fall back to tcp.
func mapSockErr(err error) error {
	if errors.Is(err, errPermission) || errors.Is(err, errAccess) {
		return ErrNoPrivilege
	}
	return fmt.Errorf("udp2raw: %w", err)
}

// parseLinkFrame strips the Ethernet header (including up to two VLAN tags) and
// parses the IPv4/TCP packet behind it. Kept platform independent so it can be
// unit tested anywhere.
func parseLinkFrame(pkt []byte) (segment, bool) {
	if len(pkt) < ethernetHeaderLen {
		return segment{}, false
	}
	etherType := binary.BigEndian.Uint16(pkt[12:14])
	off := ethernetHeaderLen
	for range 2 {
		if etherType != 0x8100 && etherType != 0x88a8 {
			break
		}
		if len(pkt) < off+4 {
			return segment{}, false
		}
		etherType = binary.BigEndian.Uint16(pkt[off+2 : off+4])
		off += 4
	}
	if etherType != 0x0800 {
		return segment{}, false
	}
	return parseSegment(pkt[off:])
}
