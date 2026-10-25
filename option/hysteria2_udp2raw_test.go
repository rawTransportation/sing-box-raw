package option

import (
	"testing"

	"github.com/sagernet/sing/common/json"
	"github.com/stretchr/testify/require"
)

func TestHysteria2UDP2RawOptions(t *testing.T) {
	t.Run("inbound", func(t *testing.T) {
		var options Hysteria2InboundOptions
		err := json.Unmarshal([]byte(`{
			"type": "hysteria2",
			"listen": "0.0.0.0",
			"listen_port": 443,
			"udp2raw": {
				"mode": "faketcp",
				"port": 8443,
				"auth": "s3cret",
				"mtu": 1300,
				"camouflage": "tls",
				"sni": "example.com",
				"faketcp": {
					"ttl": 64,
					"mss": 1200
				},
				"tcp": {
					"listen": ":8443"
				},
				"auto_firewall": true,
				"max_sessions": 16,
				"max_sessions_per_ip": 4
			}
		}`), &options)
		require.NoError(t, err)
		require.NotNil(t, options.UDP2Raw)
		require.Equal(t, "faketcp", options.UDP2Raw.Mode)
		require.Equal(t, uint16(8443), options.UDP2Raw.Port)
		require.Equal(t, "s3cret", options.UDP2Raw.Auth)
		require.Equal(t, 1300, options.UDP2Raw.MTU)
		require.Equal(t, "tls", options.UDP2Raw.Camouflage)
		require.Equal(t, "example.com", options.UDP2Raw.SNI)
		require.Equal(t, uint16(1200), options.UDP2Raw.FakeTCP.MSS)
		require.Equal(t, ":8443", options.UDP2Raw.TCP.Listen)
		require.True(t, options.UDP2Raw.AutoFirewall)
		require.Equal(t, 16, options.UDP2Raw.MaxSessions)
		require.Equal(t, 4, options.UDP2Raw.MaxSessionsPerIP)
	})
	t.Run("outbound", func(t *testing.T) {
		var options Hysteria2OutboundOptions
		err := json.Unmarshal([]byte(`{
			"type": "hysteria2",
			"server": "example.com",
			"server_port": 443,
			"udp2raw": {
				"mode": "tcp",
				"port": 8443
			}
		}`), &options)
		require.NoError(t, err)
		require.NotNil(t, options.UDP2Raw)
		require.Equal(t, "tcp", options.UDP2Raw.Mode)
		require.Equal(t, uint16(8443), options.UDP2Raw.Port)
	})
}
