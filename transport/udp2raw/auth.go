package udp2raw

import (
	"crypto/hmac"
	crand "crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"sync"
	"time"
)

const (
	helloMagic = "H2R1"
	// helloPlainLen is the payload of an unauthenticated HELLO: just the nonce.
	helloPlainLen = 8
	// helloAuthLen is magic(4) | timestamp(8) | nonce(8) | tag(16).
	helloAuthLen = 4 + 8 + 8 + 16

	helloTimeWindow = 60 * time.Second
)

var errBadHello = errors.New("udp2raw: invalid hello")

// newNonce returns a fresh nonce used to tie a HELLO to its HELLO_ACK.
func newNonce() [8]byte {
	var n [8]byte
	if _, err := crand.Read(n[:]); err != nil {
		panic("udp2raw: no randomness available: " + err.Error())
	}
	return n
}

// buildHello renders the HELLO payload. With an empty auth string only the
// nonce is sent; otherwise a truncated HMAC binds the nonce to a timestamp.
//
// The HMAC deliberately does not cover addresses: a client behind NAT cannot
// know the source address the server will see, so binding them would break
// every NATed deployment. This is an admission check, not authentication of the
// path.
func buildHello(auth string, nonce [8]byte, now time.Time) []byte {
	if auth == "" {
		b := make([]byte, helloPlainLen)
		copy(b, nonce[:])
		return b
	}
	b := make([]byte, helloAuthLen)
	copy(b, helloMagic)
	binary.BigEndian.PutUint64(b[4:], uint64(now.UnixMilli()))
	copy(b[12:20], nonce[:])
	copy(b[20:], helloTag(auth, b[:20]))
	return b
}

func helloTag(auth string, prefix []byte) []byte {
	mac := hmac.New(sha256.New, []byte(auth))
	mac.Write(prefix)
	sum := mac.Sum(nil)
	return sum[:16]
}

// verifyHello validates a HELLO and returns the nonce to echo.
func verifyHello(auth string, payload []byte, now time.Time) ([8]byte, error) {
	var nonce [8]byte
	if auth == "" {
		if len(payload) != helloPlainLen {
			return nonce, errBadHello
		}
		copy(nonce[:], payload)
		return nonce, nil
	}
	if len(payload) != helloAuthLen || string(payload[:4]) != helloMagic {
		return nonce, errBadHello
	}
	ts := int64(binary.BigEndian.Uint64(payload[4:12]))
	if d := now.Sub(time.UnixMilli(ts)); d > helloTimeWindow || d < -helloTimeWindow {
		return nonce, errBadHello
	}
	copy(nonce[:], payload[12:20])
	want := helloTag(auth, payload[:20])
	if subtle.ConstantTimeCompare(want, payload[20:]) != 1 {
		return nonce, errBadHello
	}
	return nonce, nil
}

// replayCache rejects nonces seen within the timestamp window.
type replayCache struct {
	mu        sync.Mutex
	seen      map[[8]byte]int64
	lastSweep time.Time
}

func newReplayCache() *replayCache {
	return &replayCache{seen: make(map[[8]byte]int64), lastSweep: time.Now()}
}

func (r *replayCache) accept(n [8]byte, now time.Time) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.seen[n]; ok {
		return false
	}
	r.seen[n] = now.UnixNano()
	if now.Sub(r.lastSweep) > 30*time.Second || len(r.seen) > 1<<16 {
		cutoff := now.Add(-2 * helloTimeWindow).UnixNano()
		for k, v := range r.seen {
			if v < cutoff {
				delete(r.seen, k)
			}
		}
		r.lastSweep = now
	}
	return true
}
