//go:build linux || android

package udp2raw

import (
	"net/netip"
	"os"
	"sync"
	"testing"
	"time"
)

// TestFakeTCPLoopback exercises the real AF_PACKET/raw socket path on the
// loopback interface. It needs CAP_NET_RAW, so it is skipped for normal users
// and runs under sudo in CI.
func TestFakeTCPLoopback(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root or CAP_NET_RAW")
	}
	loop := netip.MustParseAddr("127.0.0.1")
	sPort := freeTCPPort(t)
	cPort := freeTCPPort(t)

	serverEP, err := openRawEndpoint(endpointFilter{
		server: true, listenPort: sPort, listenIP: loop, mss: defaultMSS,
	})
	if err != nil {
		t.Fatalf("open server endpoint: %v", err)
	}
	defer serverEP.close()
	clientEP, err := openRawEndpoint(endpointFilter{
		server: false, serverIP: loop, serverPort: sPort,
		localIP: loop, localPort: cPort, mss: defaultMSS,
	})
	if err != nil {
		t.Fatalf("open client endpoint: %v", err)
	}
	defer clientEP.close()

	cfg := testSessionCfg()
	cfg.handshakeTimeout = 5 * time.Second
	clientAddr := netip.AddrPortFrom(loop, uint16(cPort))
	serverAddr := netip.AddrPortFrom(loop, uint16(sPort))

	serverData := make(chan []byte, 8)
	clientData := make(chan []byte, 8)

	cs := newSession(true, clientEP, clientAddr, serverAddr, cfg, nil)
	cs.deliver = func(b []byte) { clientData <- b }

	var (
		ssMu sync.Mutex
		ss   *session
	)
	pumpRaw(t, serverEP, func(seg segment) {
		ssMu.Lock()
		defer ssMu.Unlock()
		if ss == nil {
			if seg.Flags&tcpFlagSYN == 0 || seg.Flags&tcpFlagACK != 0 {
				return
			}
			s := newSession(false, serverEP, serverAddr, clientAddr, cfg, nil)
			s.deliver = func(b []byte) { serverData <- b }
			ss = s
			_ = s.acceptSyn(seg)
			return
		}
		ss.handleSegment(seg)
	})
	pumpRaw(t, clientEP, cs.onSegment)

	if err := cs.startClient(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(6 * time.Second)
	for !cs.Established() && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if !cs.Established() {
		t.Fatal("client did not establish over loopback")
	}

	if err := cs.sendDatagram([]byte("loopback-hello")); err != nil {
		t.Fatal(err)
	}
	if got := waitFor(t, serverData, 3*time.Second); string(got) != "loopback-hello" {
		t.Fatalf("server received %q", got)
	}

	ssMu.Lock()
	serverSess := ss
	ssMu.Unlock()
	if serverSess == nil {
		t.Fatal("no server session")
	}
	if err := serverSess.sendDatagram([]byte("loopback-reply")); err != nil {
		t.Fatal(err)
	}
	if got := waitFor(t, clientData, 3*time.Second); string(got) != "loopback-reply" {
		t.Fatalf("client received %q", got)
	}
}
