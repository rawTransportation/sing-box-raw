package udp2raw

import (
	"testing"
	"time"
)

func TestHelloRoundTripWithAuth(t *testing.T) {
	now := time.Now()
	nonce := newNonce()
	payload := buildHello("s3cret", nonce, now)
	got, err := verifyHello("s3cret", payload, now)
	if err != nil {
		t.Fatal(err)
	}
	if got != nonce {
		t.Fatalf("nonce mismatch")
	}
	if _, err := verifyHello("other", payload, now); err == nil {
		t.Fatal("wrong secret accepted")
	}
	tampered := append([]byte(nil), payload...)
	tampered[20] ^= 0xff
	if _, err := verifyHello("s3cret", tampered, now); err == nil {
		t.Fatal("tampered tag accepted")
	}
	if _, err := verifyHello("s3cret", payload, now.Add(2*helloTimeWindow)); err == nil {
		t.Fatal("stale hello accepted")
	}
}

func TestHelloWithoutAuth(t *testing.T) {
	nonce := newNonce()
	payload := buildHello("", nonce, time.Now())
	if len(payload) != helloPlainLen {
		t.Fatalf("unexpected payload length %d", len(payload))
	}
	got, err := verifyHello("", payload, time.Now())
	if err != nil || got != nonce {
		t.Fatalf("plain hello rejected: %v", err)
	}
	if _, err := verifyHello("", make([]byte, 4), time.Now()); err == nil {
		t.Fatal("short hello accepted")
	}
}

func TestReplayCache(t *testing.T) {
	r := newReplayCache()
	now := time.Now()
	n := newNonce()
	if !r.accept(n, now) {
		t.Fatal("first use rejected")
	}
	if r.accept(n, now.Add(time.Second)) {
		t.Fatal("replay accepted")
	}
	other := newNonce()
	if !r.accept(other, now.Add(time.Second)) {
		t.Fatal("fresh nonce rejected")
	}
}
