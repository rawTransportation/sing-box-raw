//go:build linux || android

package udp2raw

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
)

// firewallCleanup removes whatever rules setupRSTRules installed.
type firewallCleanup struct {
	commands [][]string
}

func (f *firewallCleanup) Close() error {
	for _, c := range f.commands {
		_ = exec.Command(c[0], c[1:]...).Run()
	}
	return nil
}

// setupRSTRules suppresses the kernel's RST for the tunnel port.
//
// Two rules are installed: one drops inbound SYNs (so the local stack never
// creates a socket and never refuses), the other drops outbound RSTs as a
// belt-and-braces measure. Our capture uses AF_PACKET, which taps before
// netfilter, so dropping inbound packets does not blind the tunnel.
func setupRSTRules(port int) (io.Closer, error) {
	if os.Geteuid() != 0 {
		return nil, errors.New("root is required")
	}
	p := strconv.Itoa(port)

	if _, err := exec.LookPath("nft"); err == nil {
		setup := [][]string{
			{"nft", "add", "table", "inet", "h2raw"},
			{"nft", "add", "chain", "inet", "h2raw", "pre", "{ type filter hook prerouting priority -300; }"},
			{"nft", "add", "rule", "inet", "h2raw", "pre", "tcp", "dport", p, "drop"},
			{"nft", "add", "chain", "inet", "h2raw", "out", "{ type filter hook output priority -300; }"},
			{"nft", "add", "rule", "inet", "h2raw", "out", "tcp", "sport", p, "tcp", "flags", "rst", "drop"},
		}
		ok := true
		for _, c := range setup {
			if out, err := exec.Command(c[0], c[1:]...).CombinedOutput(); err != nil {
				_ = out
				ok = false
				break
			}
		}
		if ok {
			return &firewallCleanup{commands: [][]string{
				{"nft", "delete", "table", "inet", "h2raw"},
			}}, nil
		}
		// Leave no half-built table behind, then try iptables.
		_ = exec.Command("nft", "delete", "table", "inet", "h2raw").Run()
	}

	if _, err := exec.LookPath("iptables"); err != nil {
		return nil, fmt.Errorf("neither nft nor iptables is available; "+
			"add these rules manually: iptables -t raw -I PREROUTING -p tcp --dport %s -j DROP ; "+
			"iptables -t raw -I OUTPUT -p tcp --sport %s --tcp-flags RST RST -j DROP", p, p)
	}
	add := [][]string{
		{"iptables", "-t", "raw", "-I", "PREROUTING", "-p", "tcp", "--dport", p, "-j", "DROP"},
		{"iptables", "-t", "raw", "-I", "OUTPUT", "-p", "tcp", "--sport", p, "--tcp-flags", "RST", "RST", "-j", "DROP"},
	}
	for _, c := range add {
		if out, err := exec.Command(c[0], c[1:]...).CombinedOutput(); err != nil {
			return nil, fmt.Errorf("iptables failed: %v: %s", err, out)
		}
	}
	return &firewallCleanup{commands: [][]string{
		{"iptables", "-t", "raw", "-D", "PREROUTING", "-p", "tcp", "--dport", p, "-j", "DROP"},
		{"iptables", "-t", "raw", "-D", "OUTPUT", "-p", "tcp", "--sport", p, "--tcp-flags", "RST", "RST", "-j", "DROP"},
	}}, nil
}
