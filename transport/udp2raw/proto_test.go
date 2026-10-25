package udp2raw

import (
	"bytes"
	"testing"
)

func TestFrameRoundTrip(t *testing.T) {
	payload := []byte("hello")
	buf, err := appendFrame(nil, frameData, payload, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(buf) != frameHeaderLen+len(payload) {
		t.Fatalf("unexpected frame size %d", len(buf))
	}
	ft, got, err := parseFrame(buf)
	if err != nil {
		t.Fatal(err)
	}
	if ft != frameData || !bytes.Equal(got, payload) {
		t.Fatalf("round trip mismatch: %v %q", ft, got)
	}
}

func TestFramePaddingIsIgnored(t *testing.T) {
	buf, err := appendFrame(nil, frameData, []byte("abc"), 16)
	if err != nil {
		t.Fatal(err)
	}
	if len(buf) != frameHeaderLen+3+16 {
		t.Fatalf("padding not appended: %d", len(buf))
	}
	_, got, err := parseFrame(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "abc" {
		t.Fatalf("unexpected payload %q", got)
	}
}

func TestFrameRejectsInvalid(t *testing.T) {
	cases := [][]byte{
		nil,
		{0, 1},
		{0, 5, byte(frameData), 'a'},  // shorter than len says
		{0, 0, 0x80},                  // unknown flag
		{0xff, 0xff, byte(frameData)}, // len too large for buffer
	}
	for i, c := range cases {
		if _, _, err := parseFrame(c); err == nil {
			t.Fatalf("case %d: expected error", i)
		}
	}
}

func TestFrameTooLarge(t *testing.T) {
	big := make([]byte, maxFramePayload+1)
	if _, err := appendFrame(nil, frameData, big, 0); err == nil {
		t.Fatal("expected error for oversized payload")
	}
}

func TestControlFrames(t *testing.T) {
	for _, ft := range []frameType{frameHello, frameHelloAck, framePing, framePong, frameClose} {
		buf, err := appendFrame(nil, ft, []byte{1, 2, 3}, 0)
		if err != nil {
			t.Fatal(err)
		}
		got, payload, err := parseFrame(buf)
		if err != nil || got != ft || len(payload) != 3 {
			t.Fatalf("frame type %#x round trip failed: %v %v", ft, got, err)
		}
	}
}
