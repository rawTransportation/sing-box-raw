//go:build linux || android

package udp2raw

import (
	"errors"
	"net"
	"net/netip"
	"sync/atomic"

	"golang.org/x/sys/unix"
)

// PACKET_IGNORE_OUTGOING is not exported by older x/sys versions.
const packetIgnoreOutgoing = 23

var (
	errPermission = unix.EPERM
	errAccess     = unix.EACCES
)

// linuxEndpoint captures IPv4/TCP frames with AF_PACKET and injects crafted
// packets with an AF_INET raw socket. AF_PACKET is used instead of
// AF_INET/SOCK_RAW because packet sockets tap the device before netfilter, so
// the RST-suppression rule recommended for this port does not blind us.
type linuxEndpoint struct {
	filter endpointFilter
	recvFD int
	sendFD int
	buf    []byte
	closed atomic.Bool
}

func faketcpPlatformSupported() bool { return true }

func openRawEndpoint(f endpointFilter) (rawEndpoint, error) {
	e := &linuxEndpoint{filter: f, buf: make([]byte, 65536)}

	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, int(htons(unix.ETH_P_IP)))
	if err != nil {
		return nil, mapSockErr(err)
	}
	if f.interfaceName != "" {
		ifi, ifErr := net.InterfaceByName(f.interfaceName)
		if ifErr != nil {
			_ = unix.Close(fd)
			return nil, ifErr
		}
		if bindErr := unix.Bind(fd, &unix.SockaddrLinklayer{
			Protocol: htons(unix.ETH_P_IP),
			Ifindex:  ifi.Index,
		}); bindErr != nil {
			_ = unix.Close(fd)
			return nil, mapSockErr(bindErr)
		}
	}
	// 4MB receive buffer: at 1500B and 100k pps the default is far too small.
	_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, 4<<20)
	_ = unix.SetsockoptInt(fd, unix.SOL_PACKET, packetIgnoreOutgoing, 1)
	// A one second receive timeout keeps a goroutine blocked in recvfrom from
	// outliving Close: closing an fd does not reliably wake a blocking syscall.
	_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 1})

	sfd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.IPPROTO_RAW)
	if err != nil {
		_ = unix.Close(fd)
		return nil, mapSockErr(err)
	}
	// IPPROTO_RAW implies IP_HDRINCL; set it explicitly for older kernels.
	_ = unix.SetsockoptInt(sfd, unix.IPPROTO_IP, unix.IP_HDRINCL, 1)

	e.recvFD, e.sendFD = fd, sfd
	return e, nil
}

func (e *linuxEndpoint) recv() (segment, error) {
	for {
		n, from, err := unix.Recvfrom(e.recvFD, e.buf, 0)
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK) {
				if e.closed.Load() {
					return segment{}, net.ErrClosed
				}
				continue
			}
			return segment{}, mapSockErr(err)
		}
		if ll, ok := from.(*unix.SockaddrLinklayer); ok && ll.Pkttype == unix.PACKET_OUTGOING {
			continue
		}
		seg, ok := e.parseFrame(e.buf[:n])
		if !ok {
			continue
		}
		return seg, nil
	}
}

// parseFrame strips the link layer, then filters on the configured flow.
func (e *linuxEndpoint) parseFrame(pkt []byte) (segment, bool) {
	seg, ok := parseLinkFrame(pkt)
	if !ok || !e.match(seg) {
		return segment{}, false
	}
	return seg, true
}

func (e *linuxEndpoint) match(seg segment) bool {
	if e.filter.server {
		if seg.Dst.Port() != uint16(e.filter.listenPort) {
			return false
		}
		if e.filter.listenIP.IsValid() && !e.filter.listenIP.IsUnspecified() &&
			seg.Dst.Addr() != e.filter.listenIP {
			return false
		}
		return true
	}
	return seg.Src == netip.AddrPortFrom(e.filter.serverIP, uint16(e.filter.serverPort)) &&
		seg.Dst.Addr() == e.filter.localIP
}

func (e *linuxEndpoint) send(pkt []byte) error {
	if len(pkt) < ipv4HeaderLen {
		return errShortSegment
	}
	var dst [4]byte
	copy(dst[:], pkt[16:20])
	if err := unix.Sendto(e.sendFD, pkt, 0, &unix.SockaddrInet4{Addr: dst}); err != nil {
		if errors.Is(err, unix.EMSGSIZE) {
			return errPacketTooBig
		}
		return mapSockErr(err)
	}
	return nil
}

func (e *linuxEndpoint) close() error {
	e.closed.Store(true)
	if e.recvFD >= 0 {
		_ = unix.Close(e.recvFD)
		e.recvFD = -1
	}
	if e.sendFD >= 0 {
		_ = unix.Close(e.sendFD)
		e.sendFD = -1
	}
	return nil
}

func htons(v uint16) uint16 { return v<<8 | v>>8 }
