//go:build !linux && !android

package udp2raw

import (
	"errors"
	"io"
)

func setupRSTRules(int) (io.Closer, error) {
	return nil, errors.New("udp2raw: autoFirewall is only supported on Linux")
}
