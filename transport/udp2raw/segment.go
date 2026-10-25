package udp2raw

import (
	"encoding/binary"
	"errors"
	"net/netip"
)

const (
	ipv4HeaderLen = 20
	ipv4ProtoTCP  = 6

	tcpFlagFIN = 0x01
	tcpFlagSYN = 0x02
	tcpFlagRST = 0x04
	tcpFlagPSH = 0x08
	tcpFlagACK = 0x10

	// tcpOptionMaxSegSize / WindowScale / SackPermitted / Timestamps / Sack.
	tcpOptEnd        = 0
	tcpOptNOP        = 1
	tcpOptMSS        = 2
	tcpOptWScale     = 3
	tcpOptSackPerm   = 4
	tcpOptSack       = 5
	tcpOptTimestamps = 8
)

// sackBlock is one SACK range: [Left, Right).
type sackBlock struct {
	Left  uint32
	Right uint32
}

// tcpOptions is the parsed or to-be-built TCP option set.
type tcpOptions struct {
	MSS            uint16
	WindowScale    uint8
	HasMSS         bool
	HasWindowScale bool
	HasTimestamps  bool
	HasSackPerm    bool
	TSVal          uint32
	TSEcr          uint32
	Sack           []sackBlock
}

// segment is one IPv4/TCP segment. Payload aliases the capture buffer.
type segment struct {
	Src, Dst   netip.AddrPort
	Seq, Ack   uint32
	Flags      uint8
	Window     uint16
	Payload    []byte
	TCPOptions tcpOptions
}

// parseSegment decodes an IPv4/TCP packet. It rejects fragments and anything
// that does not look like a single, complete TCP segment.
func parseSegment(b []byte) (segment, bool) {
	var s segment
	if len(b) < ipv4HeaderLen {
		return s, false
	}
	if b[0]>>4 != 4 {
		return s, false
	}
	ihl := int(b[0]&0x0f) * 4
	if ihl < ipv4HeaderLen || len(b) < ihl+20 {
		return s, false
	}
	totalLen := int(binary.BigEndian.Uint16(b[2:]))
	if totalLen < ihl+20 || totalLen > len(b) {
		return s, false
	}
	// Fragment offset or MF set: we never send fragments and cannot reassemble.
	if binary.BigEndian.Uint16(b[6:])&0x3fff != 0 {
		return s, false
	}
	if b[9] != ipv4ProtoTCP {
		return s, false
	}
	var srcIP, dstIP [4]byte
	copy(srcIP[:], b[12:16])
	copy(dstIP[:], b[16:20])

	tcp := b[ihl:totalLen]
	dataOff := int(tcp[12]>>4) * 4
	if dataOff < 20 || dataOff > len(tcp) {
		return s, false
	}
	s.Src = netip.AddrPortFrom(netip.AddrFrom4(srcIP), binary.BigEndian.Uint16(tcp[0:]))
	s.Dst = netip.AddrPortFrom(netip.AddrFrom4(dstIP), binary.BigEndian.Uint16(tcp[2:]))
	s.Seq = binary.BigEndian.Uint32(tcp[4:])
	s.Ack = binary.BigEndian.Uint32(tcp[8:])
	s.Flags = tcp[13]
	s.Window = binary.BigEndian.Uint16(tcp[14:])
	s.Payload = tcp[dataOff:]
	if dataOff > 20 {
		s.TCPOptions = parseTCPOptions(tcp[20:dataOff])
	}
	return s, true
}

func parseTCPOptions(b []byte) tcpOptions {
	var o tcpOptions
	for len(b) > 0 {
		kind := b[0]
		if kind == tcpOptEnd {
			break
		}
		if kind == tcpOptNOP {
			b = b[1:]
			continue
		}
		if len(b) < 2 {
			break
		}
		l := int(b[1])
		if l < 2 || l > len(b) {
			break
		}
		opt := b[:l]
		switch kind {
		case tcpOptMSS:
			if l == 4 {
				o.MSS = binary.BigEndian.Uint16(opt[2:])
				o.HasMSS = true
			}
		case tcpOptWScale:
			if l == 3 {
				o.WindowScale = opt[2]
				o.HasWindowScale = true
			}
		case tcpOptSackPerm:
			o.HasSackPerm = true
		case tcpOptTimestamps:
			if l == 10 {
				o.HasTimestamps = true
				o.TSVal = binary.BigEndian.Uint32(opt[2:])
				o.TSEcr = binary.BigEndian.Uint32(opt[6:])
			}
		case tcpOptSack:
			if l >= 10 && (l-2)%8 == 0 {
				o.Sack = o.Sack[:0]
				for i := 2; i+8 <= l; i += 8 {
					o.Sack = append(o.Sack, sackBlock{
						Left:  binary.BigEndian.Uint32(opt[i:]),
						Right: binary.BigEndian.Uint32(opt[i+4:]),
					})
				}
			}
		}
		b = b[l:]
	}
	return o
}

// buildTCPOptions renders options in the same order a modern Linux stack does:
// MSS, SACK permitted, timestamps, NOP+window scale, then SACK blocks. The
// result is padded to a multiple of four bytes.
func buildTCPOptions(o tcpOptions) []byte {
	var b []byte
	if o.HasMSS {
		b = append(b, tcpOptMSS, 4)
		b = binary.BigEndian.AppendUint16(b, o.MSS)
	}
	if o.HasSackPerm {
		b = append(b, tcpOptSackPerm, 2)
	}
	if o.HasTimestamps {
		b = append(b, tcpOptTimestamps, 10)
		b = binary.BigEndian.AppendUint32(b, o.TSVal)
		b = binary.BigEndian.AppendUint32(b, o.TSEcr)
	}
	if o.HasWindowScale {
		b = append(b, tcpOptNOP, tcpOptWScale, 3, o.WindowScale)
	}
	if n := len(o.Sack); n > 0 {
		if n > 3 {
			n = 3
		}
		b = append(b, tcpOptSack, byte(2+8*n))
		for _, blk := range o.Sack[:n] {
			b = binary.BigEndian.AppendUint32(b, blk.Left)
			b = binary.BigEndian.AppendUint32(b, blk.Right)
		}
	}
	for len(b)%4 != 0 {
		b = append(b, tcpOptNOP)
	}
	return b
}

// buildSegment renders a complete IPv4/TCP packet.
func buildSegment(s segment, opts tcpOptions, ipID uint16, ttl uint8) ([]byte, error) {
	tcpOpt := buildTCPOptions(opts)
	tcpHdrLen := 20 + len(tcpOpt)
	total := ipv4HeaderLen + tcpHdrLen + len(s.Payload)
	if total > 0xffff {
		return nil, errFrameTooLarge
	}
	ip := make([]byte, 0, total)
	// IPv4 header.
	ip = append(ip,
		0x45, 0,
		0, 0, // total length, filled below
		0, 0, // identification, filled below
		0x40, 0, // DF
		ttl, ipv4ProtoTCP,
		0, 0, // checksum, filled below
	)
	src, dst := s.Src.Addr().As4(), s.Dst.Addr().As4()
	ip = append(ip, src[:]...)
	ip = append(ip, dst[:]...)
	binary.BigEndian.PutUint16(ip[2:], uint16(total))
	binary.BigEndian.PutUint16(ip[4:], ipID)
	binary.BigEndian.PutUint16(ip[10:], ipv4Checksum(ip[:ipv4HeaderLen]))

	// TCP header.
	tcp := make([]byte, 0, tcpHdrLen+len(s.Payload))
	tcp = binary.BigEndian.AppendUint16(tcp, s.Src.Port())
	tcp = binary.BigEndian.AppendUint16(tcp, s.Dst.Port())
	tcp = binary.BigEndian.AppendUint32(tcp, s.Seq)
	tcp = binary.BigEndian.AppendUint32(tcp, s.Ack)
	tcp = append(tcp, byte(tcpHdrLen/4)<<4, s.Flags)
	tcp = binary.BigEndian.AppendUint16(tcp, s.Window)
	tcp = append(tcp, 0, 0, 0, 0) // checksum + urgent pointer
	tcp = append(tcp, tcpOpt...)
	tcp = append(tcp, s.Payload...)

	sum := checksumAdd(0, src[:])
	sum = checksumAdd(sum, dst[:])
	sum += 6 // protocol
	sum += uint32(tcpHdrLen + len(s.Payload))
	sum = checksumAdd(sum, tcp)
	binary.BigEndian.PutUint16(tcp[16:], finishChecksum(sum))

	return append(ip, tcp...), nil
}

func ipv4Checksum(hdr []byte) uint16 {
	return finishChecksum(checksumAdd(0, hdr))
}

// checksumAdd folds b into the running one's complement sum.
func checksumAdd(sum uint32, b []byte) uint32 {
	for len(b) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(b))
		b = b[2:]
	}
	if len(b) == 1 {
		sum += uint32(b[0]) << 8
	}
	return sum
}

func finishChecksum(sum uint32) uint16 {
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

var errShortSegment = errors.New("udp2raw: short segment")
