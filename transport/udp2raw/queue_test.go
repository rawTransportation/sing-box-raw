package udp2raw

import (
	"os"
	"testing"
	"time"
)

func TestQueueDeadline(t *testing.T) {
	q := newRecvQueue(4)
	q.setDeadline(time.Now().Add(30 * time.Millisecond))
	_, _, err := q.pop(make([]byte, 16))
	if err == nil || !os.IsTimeout(err) {
		t.Fatalf("expected timeout, got %v", err)
	}
}

func TestQueuePushPop(t *testing.T) {
	q := newRecvQueue(4)
	if !q.push([]byte("x"), sessionAddr("1.2.3.4:5")) {
		t.Fatal("push failed")
	}
	buf := make([]byte, 8)
	n, addr, err := q.pop(buf)
	if err != nil || n != 1 || buf[0] != 'x' || addr.String() != "1.2.3.4:5" {
		t.Fatalf("pop = %d %v %v", n, addr, err)
	}
}

func TestQueueCloseUnblocks(t *testing.T) {
	q := newRecvQueue(4)
	go func() {
		time.Sleep(20 * time.Millisecond)
		q.close(ErrClosed)
	}()
	start := time.Now()
	_, _, err := q.pop(make([]byte, 8))
	if err != ErrClosed {
		t.Fatalf("expected ErrClosed, got %v", err)
	}
	if time.Since(start) > time.Second {
		t.Fatal("close did not unblock pop")
	}
}

func TestQueueDropsWhenFull(t *testing.T) {
	q := newRecvQueue(1)
	if !q.push([]byte("a"), sessionAddr("1.1.1.1:1")) {
		t.Fatal("first push failed")
	}
	if q.push([]byte("b"), sessionAddr("1.1.1.1:1")) {
		t.Fatal("expected drop when full")
	}
}
