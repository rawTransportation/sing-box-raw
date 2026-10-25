package udp2raw

import "net/netip"

// sessionAddr is the pseudo remote address handed to the QUIC stack for a
// session. Its string form is the peer's "ip:port", which is what quic-go uses
// as a connection key and passes back to WriteTo.
type sessionAddr string

func (a sessionAddr) Network() string { return "udp" }
func (a sessionAddr) String() string  { return string(a) }

// localAddr is the local pseudo address of a client connection. It is
// deliberately not a *net.UDPAddr so nothing tries to enable UDP-only socket
// options on it.
type localAddr string

func (a localAddr) Network() string { return "udp" }
func (a localAddr) String() string  { return string(a) }

func addrPortToSessionAddr(ap netip.AddrPort) sessionAddr {
	return sessionAddr(ap.String())
}
