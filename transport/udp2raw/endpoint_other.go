//go:build !linux && !android && !windows

package udp2raw

import "errors"

var (
	errPermission = errors.New("permission denied")
	errAccess     = errPermission
)

func faketcpPlatformSupported() bool { return false }

func openRawEndpoint(endpointFilter) (rawEndpoint, error) { return nil, ErrUnsupported }
