package udp2raw

import (
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"
)

// memEndpoint is an in-process rawEndpoint used to exercise the session state
// machine without any privileges. Packets are serialized and parsed exactly
// like on a real wire, so header/checksum bugs surface here too.
type memEndpoint struct {
	in   chan []byte
	peer *memEndpoint
	buf  []byte
	done chan struct{}

	mu      sync.Mutex
	closed  bool
	reorder bool
	held    []byte
	onSend  func(pkt []byte) bool
}

func newMemPair() (*memEndpoint, *memEndpoint) {
	a := &memEndpoint{in: make(chan []byte, 1024), buf: make([]byte, 65536), done: make(chan struct{})}
	b := &memEndpoint{in: make(chan []byte, 1024), buf: make([]byte, 65536), done: make(chan struct{})}
	a.peer, b.peer = b, a
	return a, b
}

func (e *memEndpoint) setHook(f func(pkt []byte) bool) {
	e.mu.Lock()
	e.onSend = f
	e.mu.Unlock()
}

func (e *memEndpoint) setReorder(v bool) {
	e.mu.Lock()
	e.reorder = v
	e.mu.Unlock()
}

func (e *memEndpoint) send(pkt []byte) error {
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return netErrClosed
	}
	hook := e.onSend
	reorder := e.reorder
	held := e.held
	e.mu.Unlock()

	if hook != nil && !hook(pkt) {
		return nil
	}

	if reorder && held == nil {
		e.mu.Lock()
		e.held = append([]byte(nil), pkt...)
		e.mu.Unlock()
		return nil
	}
	if reorder {
		e.mu.Lock()
		e.held = nil
		e.mu.Unlock()
	}

	e.peer.push(append([]byte(nil), pkt...))
	if held != nil {
		e.peer.push(held)
	}
	return nil
}

func (e *memEndpoint) push(pkt []byte) {
	select {
	case e.in <- pkt:
	default:
	}
}

func (e *memEndpoint) recv() (segment, error) {
	for {
		select {
		case pkt := <-e.in:
			e.mu.Lock()
			copy(e.buf, pkt)
			e.mu.Unlock()
			seg, ok := parseSegment(e.buf[:len(pkt)])
			if !ok {
				continue
			}
			return seg, nil
		case <-e.done:
			return segment{}, netErrClosed
		}
	}
}

func (e *memEndpoint) close() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if !e.closed {
		e.closed = true
		close(e.done)
	}
	return nil
}

var netErrClosed = errors.New("mem endpoint closed")

func testSessionCfg() sessionConfig {
	return sessionConfig{
		keepAlive:        100 * time.Millisecond,
		idleTimeout:      time.Second,
		handshakeTimeout: 2 * time.Second,
		mss:              defaultMSS,
		ttl:              defaultTTL,
		windowScale:      defaultWindowScale,
		maxPayload:       1400,
	}
}

func pumpRaw(t *testing.T, ep rawEndpoint, handle func(segment)) {
	t.Helper()
	go func() {
		for {
			seg, err := ep.recv()
			if err != nil {
				return
			}
			handle(seg)
		}
	}()
}

func pump(t *testing.T, ep *memEndpoint, handle func(segment)) {
	t.Helper()
	pumpRaw(t, ep, handle)
}

func waitFor(t *testing.T, ch <-chan []byte, timeout time.Duration) []byte {
	t.Helper()
	select {
	case b := <-ch:
		return b
	case <-time.After(timeout):
		t.Fatal("timed out waiting for datagram")
		return nil
	}
}

func mustAddr(t *testing.T, s string) netip.AddrPort {
	t.Helper()
	a, err := netip.ParseAddrPort(s)
	if err != nil {
		t.Fatalf("bad addr %q: %v", s, err)
	}
	return a
}
