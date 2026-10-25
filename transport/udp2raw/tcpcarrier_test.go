package udp2raw

import (
	"bytes"
	"net"
	"strconv"
	"testing"
	"time"
)

func freeTCPPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return port
}

func startTCPPair(t *testing.T, camo string) (net.PacketConn, net.PacketConn) {
	t.Helper()
	port := freeTCPPort(t)
	srv, err := NewServerConn(ServerConfig{
		ListenIP:   net.IPv4(127, 0, 0, 1),
		Port:       port,
		Mode:       ModeTCP,
		Camouflage: camo,
		SNI:        "example.com",
		TCP:        TCPConfig{Listen: net.JoinHostPort("127.0.0.1", strconv.Itoa(port))},
	})
	if err != nil {
		t.Fatalf("server: %v", err)
	}
	cli, err := NewClientConn(ClientConfig{
		ServerAddr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port},
		Port:       port,
		Mode:       ModeTCP,
		Camouflage: camo,
		SNI:        "example.com",
		TCP:        TCPConfig{DialTimeout: 2 * time.Second},
	})
	if err != nil {
		_ = srv.Close()
		t.Fatalf("client: %v", err)
	}
	t.Cleanup(func() {
		_ = cli.Close()
		_ = srv.Close()
	})
	return cli, srv
}

func TestTCPCarrierEndToEnd(t *testing.T) {
	cli, srv := startTCPPair(t, CamouflageNone)
	payloads := [][]byte{
		[]byte("a"),
		bytes.Repeat([]byte("b"), 1200),
		bytes.Repeat([]byte("c"), 64),
	}
	for _, p := range payloads {
		if _, err := cli.WriteTo(p, nil); err != nil {
			t.Fatalf("client write: %v", err)
		}
	}

	buf := make([]byte, 2048)
	for _, want := range payloads {
		_ = srv.SetReadDeadline(time.Now().Add(3 * time.Second))
		n, addr, err := srv.ReadFrom(buf)
		if err != nil {
			t.Fatalf("server read: %v", err)
		}
		if !bytes.Equal(buf[:n], want) {
			t.Fatalf("server got %d bytes, want %d", n, len(want))
		}
		if addr.Network() != "udp" {
			t.Fatalf("unexpected network %q", addr.Network())
		}
		// Echo back so the reverse direction is covered too.
		if _, err := srv.WriteTo(buf[:n], addr); err != nil {
			t.Fatalf("server write: %v", err)
		}
	}

	for _, want := range payloads {
		_ = cli.SetReadDeadline(time.Now().Add(3 * time.Second))
		n, _, err := cli.ReadFrom(buf)
		if err != nil {
			t.Fatalf("client read: %v", err)
		}
		if !bytes.Equal(buf[:n], want) {
			t.Fatalf("echo mismatch: %d vs %d bytes", n, len(want))
		}
	}
}

func TestTCPCarrierWithCamouflage(t *testing.T) {
	cli, srv := startTCPPair(t, CamouflageTLS)
	if _, err := cli.WriteTo([]byte("tls-camo"), nil); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	_ = srv.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, addr, err := srv.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "tls-camo" {
		t.Fatalf("got %q", buf[:n])
	}
	if _, err := srv.WriteTo([]byte("ok"), addr); err != nil {
		t.Fatal(err)
	}
	_ = cli.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, _, err = cli.ReadFrom(buf)
	if err != nil || string(buf[:n]) != "ok" {
		t.Fatalf("client echo: %q %v", buf[:n], err)
	}
}

func TestServerConnLocalAddr(t *testing.T) {
	port := freeTCPPort(t)
	srv, err := NewServerConn(ServerConfig{
		ListenIP: net.IPv4(127, 0, 0, 1),
		Port:     port,
		Mode:     ModeTCP,
		TCP:      TCPConfig{Listen: net.JoinHostPort("127.0.0.1", strconv.Itoa(port))},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	if got := srv.LocalAddr().String(); got != "127.0.0.1:"+strconv.Itoa(port) {
		t.Fatalf("LocalAddr = %q", got)
	}
}

func TestUnknownSessionWriteFails(t *testing.T) {
	port := freeTCPPort(t)
	srv, err := NewServerConn(ServerConfig{
		Port: port,
		Mode: ModeTCP,
		TCP:  TCPConfig{Listen: net.JoinHostPort("127.0.0.1", strconv.Itoa(port))},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	if _, err := srv.WriteTo([]byte("x"), sessionAddr("192.0.2.9:1234")); err == nil {
		t.Fatal("expected error for unknown session")
	}
}
