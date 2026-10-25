// Package udp2raw implements a udp2raw-style transport for Hysteria2.
//
// It carries QUIC datagrams inside a channel that looks like a TCP flow to
// middleboxes, in order to dodge UDP/QoS classification and QUIC fingerprinting.
// The layer deliberately does not encrypt anything: confidentiality is provided
// by QUIC/TLS above it.
//
// Two carriers are provided:
//
//   - faketcp crafts IPv4/TCP segments on the wire without involving the kernel
//     TCP stack. It is unreliable by design (no retransmission, no flow control),
//     which keeps QUIC's own loss recovery meaningful. It needs raw socket
//     privileges (CAP_NET_RAW on Linux, the WinDivert driver on Windows).
//   - tcp runs over a real TCP connection with length-prefixed frames. It works
//     everywhere, including iOS, at the cost of TCP-over-TCP head-of-line
//     blocking.
//
// Both ends expose a net.PacketConn, which is the only seam Hysteria2 needs:
// client.Config.ConnFactory on the client and server.Config.Conn on the server.
package udp2raw

import (
	"encoding/binary"
	"errors"
	"math/rand/v2"
)

const (
	// frameHeaderLen is the size of the type/length prefix of every frame.
	frameHeaderLen = 3
	// maxFramePayload is the largest datagram a frame can carry.
	maxFramePayload = 65535
)

// frameType marks what a frame carries.
type frameType uint8

const (
	frameData     frameType = 1 << 0
	frameHello    frameType = 1 << 1
	framePing     frameType = 1 << 2
	framePong     frameType = 1 << 3
	frameClose    frameType = 1 << 4
	frameHelloAck frameType = 1 << 5

	frameKnownMask = frameData | frameHello | framePing | framePong | frameClose | frameHelloAck
)

var (
	errFrameTooLarge = errors.New("udp2raw: frame payload too large")
	errShortFrame    = errors.New("udp2raw: short frame")
)

// appendFrame appends one frame to dst.
//
// Layout: len(2) | flags(1) | payload | padding. The length field covers the
// payload only, so the receiver can strip padding without extra bookkeeping.
func appendFrame(dst []byte, t frameType, payload []byte, padding int) ([]byte, error) {
	if len(payload) > maxFramePayload {
		return dst, errFrameTooLarge
	}
	if padding < 0 {
		padding = 0
	}
	dst = binary.BigEndian.AppendUint16(dst, uint16(len(payload)))
	dst = append(dst, byte(t))
	dst = append(dst, payload...)
	for range padding {
		dst = append(dst, byte(rand.Uint32()))
	}
	return dst, nil
}

// parseFrame splits one frame out of b.
//
// It returns the payload as a sub-slice of b; callers that keep it beyond the
// lifetime of b must copy. Padding is validated but not returned.
func parseFrame(b []byte) (frameType, []byte, error) {
	if len(b) < frameHeaderLen {
		return 0, nil, errShortFrame
	}
	n := int(binary.BigEndian.Uint16(b))
	t := frameType(b[2])
	if t&^frameKnownMask != 0 {
		return 0, nil, errShortFrame
	}
	if len(b) < frameHeaderLen+n {
		return 0, nil, errShortFrame
	}
	return t, b[frameHeaderLen : frameHeaderLen+n], nil
}

// frameWireLen reports how many bytes a frame occupies given a payload size and
// padding length, which is what the sequence number must advance by.
func frameWireLen(payloadLen, padding int) uint32 {
	return uint32(frameHeaderLen + payloadLen + padding)
}
