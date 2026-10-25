!!! quote "Changes in sing-box 1.14.0"

    :material-plus: [hop_interval_max](#hop_interval_max)  
    :material-plus: [bbr_profile](#bbr_profile)  
    :material-plus: [disable_chrome_parrot](#disable_chrome_parrot)  
    :material-plus: [realm](#realm)  
    :material-alert: [obfs](#obfstype)

!!! quote "Changes in sing-box 1.11.0"

    :material-plus: [server_ports](#server_ports)  
    :material-plus: [hop_interval](#hop_interval)

### Structure

```json
{
  "type": "hysteria2",
  "tag": "hy2-out",

  "server": "127.0.0.1",
  "server_port": 1080,
  "server_ports": [
    "2080:3000"
  ],
  "hop_interval": "",
  "hop_interval_max": "",
  "up_mbps": 100,
  "down_mbps": 100,
  "obfs": {
    "type": "salamander",
    "password": "cry_me_a_r1ver"
  },
  "password": "goofy_ahh_password",
  "network": "tcp",
  "tls": {},
  "udp2raw": {
    "mode": "auto",
    "port": 0,
    "auth": "",
    "mtu": 1500,
    "keep_alive": "15s",
    "idle_timeout": "45s",
    "handshake_timeout": "8s",
    "camouflage": "none",
    "sni": "",
    "faketcp": {
      "src_port": 0,
      "ttl": 64,
      "mss": 1460,
      "window_scale": 7,
      "gro_split": "auto",
      "raw_interface": ""
    },
    "tcp": {
      "dial_timeout": "8s"
    }
  },

  ... // QUIC Fields

  "bbr_profile": "",
  "brutal_debug": false,
  "disable_chrome_parrot": false,
  "realm": {
    "server_url": "https://realm.example.com",
    "token": "",
    "realm_id": "",
    "stun_servers": [],
    "ip_version": 0,
    "port_mapping": {
      "enabled": false,
      "timeout": "",
      "lifetime": ""
    },
    "http_client": {}
  },

  ... // Dial Fields
}
```

!!! note ""

    You can ignore the JSON Array [] tag when the content is only one item

!!! warning "Difference from official Hysteria2"

    The official Hysteria2 supports an authentication method called **userpass**,
    which essentially uses a combination of `<username>:<password>` as the actual password,
    while sing-box does not provide this alias.
    If you are planning to use sing-box with the official program,
    please note that you will need to fill the combination as the password.

### Fields

#### server

==Required==

The server address.

Conflicts with `realm`.

#### server_port

==Required==

The server port.

Ignored if `server_ports` is set.

Conflicts with `realm`.

#### server_ports

!!! question "Since sing-box 1.11.0"

Server port range list.

Conflicts with `server_port` and `realm`.

#### hop_interval

!!! question "Since sing-box 1.11.0"

Port hopping interval.

`30s` is used by default.

#### hop_interval_max

!!! question "Since sing-box 1.14.0"

Maximum port hopping interval, used for randomization.

If set, the actual hop interval will be randomly chosen between `hop_interval` and `hop_interval_max`.

#### up_mbps, down_mbps

Max bandwidth, in Mbps.

If empty, the BBR congestion control algorithm will be used instead of Hysteria CC.

#### obfs.type

QUIC traffic obfuscator type, one of `salamander` `gecko`.

Disabled if empty.

#### obfs.password

QUIC traffic obfuscator password.

#### obfs.min_packet_size

!!! question "Since sing-box 1.14.0"

Minimum on-wire packet size in bytes. Gecko only.

`512` is used by default.

#### obfs.max_packet_size

!!! question "Since sing-box 1.14.0"

Maximum on-wire packet size in bytes. Gecko only.

`1200` is used by default.

#### password

Authentication password.

#### network

Enabled network

One of `tcp` `udp`.

Both is enabled by default.

#### tls

==Required==

TLS configuration, see [TLS](/configuration/shared/tls/#outbound).

### QUIC Fields

See [QUIC Fields](/configuration/shared/quic/) for details.

#### bbr_profile

!!! question "Since sing-box 1.14.0"

BBR congestion control algorithm profile, one of `conservative` `standard` `aggressive`.

`standard` is used by default.

#### brutal_debug

Enable debug information logging for Hysteria Brutal CC.

#### disable_chrome_parrot

!!! question "Since sing-box 1.14.0"

Disable Chrome QUIC fingerprint parroting.

If it is not disabled, the client's QUIC handshake is made to parrot Chrome's, so that Hysteria traffic
is harder to identify by handshake fingerprinting.

To match Chrome, the client uses Chrome's own QUIC parameters, which override some settings:
`idle_timeout` is fixed at 30 seconds, `max_concurrent_streams` and `initial_packet_size` are replaced by
Chrome's values, and the receive windows start at Chrome's initial values before growing to the configured
maximums.

!!! warning ""

    Chrome does not declare support for Ed25519, so a server using an Ed25519 certificate will fail the
    handshake. Use an ECDSA or RSA certificate instead.

#### realm

!!! question "Since sing-box 1.14.0"

Connect to a Hysteria2 server through a Hysteria Realm rendezvous service.

Conflicts with `server`, `server_port` and `server_ports`.

The TLS SNI defaults to the host portion of `server_url`. Set `tls.server_name` to match the certificate the Hysteria2 server presents.

See [Hysteria Realm](/configuration/service/hysteria-realm/) for the rendezvous service.

#### realm.server_url

==Required==

Realm rendezvous service URL.

#### realm.token

Bearer token for the realm. Must match one of `users[].token` configured on the realm.

#### realm.realm_id

==Required==

The same slot identifier the target Hysteria2 server registered.

#### realm.stun_servers

==Required==

List of STUN servers (`host` or `host:port`) used to discover this client's public addresses.

Domain names are resolved using [`domain_resolver`](/configuration/shared/dial/#domain_resolver) from Dial Fields.

#### realm.ip_version

Restrict realm connections (STUN, hole punching, and the resulting QUIC path) to a single IP version.

`4` or `6`. Both are used if empty.

#### realm.port_mapping

Maintain a UDP port mapping on the local gateway via UPnP or NAT-PMP.

Improves hole-punching reliability behind gateways that support it.

Requires IPv4: conflicts with `"ip_version": 6`.

#### realm.port_mapping.enabled

Enable port mapping.

#### realm.port_mapping.timeout

Timeout for gateway discovery and mapping operations.

`10s` is used by default.

#### realm.port_mapping.lifetime

Lease lifetime of the mapping.

`10m` is used by default.

#### realm.http_client

HTTP client used to talk to the realm.

See [HTTP Client](/configuration/shared/http-client/) for details.

### UDP2Raw Fields

!!! question "Since sing-box 1.15.0"

Carry QUIC datagrams inside a channel that looks like a TCP flow, so that UDP blocking, UDP QoS
and QUIC fingerprinting no longer apply. Both ends must enable it with the same mode and `auth`.

With `faketcp` the segments are crafted on the wire: nothing is retransmitted and no congestion
control is applied, so QUIC keeps working exactly as it does over UDP. With `tcp` the datagrams are
framed inside a real TCP connection, which needs no privileges but suffers from TCP-over-TCP
head-of-line blocking.

`udp2raw` conflicts with `server_ports`, `hop_interval`, `hop_interval_max` and `realm`.

#### udp2raw.mode

Carrier mode, one of `auto`, `faketcp`, `tcp`.

`auto` is used by default. It prefers `faketcp` where raw sockets are available and falls back to
`tcp` when the platform or the process privileges do not allow them.

#### udp2raw.port

The carrier TCP port, `0` to reuse `server_port`.

#### udp2raw.auth

Optional pre-shared string used to admit clients with an HMAC timestamp. It is not encryption:
confidentiality is still provided by QUIC/TLS.

#### udp2raw.mtu

Path MTU the carrier must fit into, `1500` by default. Set it to the real link MTU on PPPoE (1492)
or tunneled links.

When `initial_packet_size` is unset, it is derived from this value (clamped between 1200 and 1280),
so the first QUIC packets never exceed the path MTU.

#### udp2raw.keep_alive

Interval between keep-alive packets, `15s` by default.

#### udp2raw.idle_timeout

Idle timeout after which the carrier declares the session dead, `45s` by default.

#### udp2raw.handshake_timeout

Total time allowed for the carrier handshake, `8s` by default.

#### udp2raw.camouflage

`none` or `tls`, `none` by default.

With `tls`, frames are wrapped in TLS records and a fake TLS handshake is performed, so the flow
looks like HTTPS. It is cosmetic only: the certificate is self-signed and a real TLS client cannot
complete the handshake.

#### udp2raw.sni

SNI used by `camouflage: tls`, the server host by default.

#### udp2raw.faketcp

| Field | Default | Description |
|-------|---------|-------------|
| `src_port` | `0` | Source TCP port, `0` picks a random one |
| `ttl` | `64` | TTL written into the IPv4 header |
| `mss` | `mtu - 40` | MSS advertised in the TCP options |
| `window_scale` | `7` | Window scale advertised in the TCP options |
| `gro_split` | `auto` | Split GRO batches at the MSS |
| `raw_interface` | `""` | Interface the capture socket is bound to, empty means all |

#### udp2raw.tcp

| Field | Default | Description |
|-------|---------|-------------|
| `dial_timeout` | `8s` | Timeout for dialing the carrier |

### Dial Fields

See [Dial Fields](/configuration/shared/dial/) for details.
