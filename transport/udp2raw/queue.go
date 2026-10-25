package udp2raw

import (
	"net"
	"os"
	"sync"
	"time"
)

// datagram is one queued inbound datagram. The payload is owned by the queue.
type datagram struct {
	payload []byte
	addr    net.Addr
}

// recvQueue is a bounded datagram queue with net.PacketConn deadline semantics.
type recvQueue struct {
	ch chan datagram

	mu       sync.Mutex
	deadline time.Time
	changed  chan struct{}
	err      error
}

func newRecvQueue(size int) *recvQueue {
	return &recvQueue{
		ch:      make(chan datagram, size),
		changed: make(chan struct{}),
	}
}

// push never blocks; excess datagrams are dropped, matching a full socket
// receive buffer.
func (q *recvQueue) push(payload []byte, addr net.Addr) bool {
	select {
	case q.ch <- datagram{payload: payload, addr: addr}:
		return true
	default:
		return false
	}
}

func (q *recvQueue) close(err error) {
	q.mu.Lock()
	if q.err == nil {
		q.err = err
	}
	close(q.changed)
	q.changed = make(chan struct{})
	q.mu.Unlock()
}

func (q *recvQueue) setDeadline(t time.Time) {
	q.mu.Lock()
	q.deadline = t
	close(q.changed)
	q.changed = make(chan struct{})
	q.mu.Unlock()
}

func (q *recvQueue) pop(p []byte) (int, net.Addr, error) {
	for {
		q.mu.Lock()
		if q.err != nil {
			err := q.err
			q.mu.Unlock()
			return 0, nil, err
		}
		dl := q.deadline
		changed := q.changed
		q.mu.Unlock()

		var timeout <-chan time.Time
		var timer *time.Timer
		if !dl.IsZero() {
			d := time.Until(dl)
			if d <= 0 {
				return 0, nil, os.ErrDeadlineExceeded
			}
			timer = time.NewTimer(d)
			timeout = timer.C
		}

		select {
		case d, ok := <-q.ch:
			if timer != nil {
				timer.Stop()
			}
			if !ok {
				return 0, nil, net.ErrClosed
			}
			n := copy(p, d.payload)
			return n, d.addr, nil
		case <-timeout:
			return 0, nil, os.ErrDeadlineExceeded
		case <-changed:
			if timer != nil {
				timer.Stop()
			}
		}
	}
}
