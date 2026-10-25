package udp2raw

// peerConn is the common surface of a carrier session, shared by the fake-TCP
// session and the real-TCP carrier.
type peerConn interface {
	sendDatagram([]byte) error
	close() error
}
