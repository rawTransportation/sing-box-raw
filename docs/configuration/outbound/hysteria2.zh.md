!!! quote "sing-box 1.14.0 中的更改"

    :material-plus: [hop_interval_max](#hop_interval_max)  
    :material-plus: [bbr_profile](#bbr_profile)  
    :material-plus: [disable_chrome_parrot](#disable_chrome_parrot)  
    :material-plus: [realm](#realm)  
    :material-alert: [obfs](#obfstype)

!!! quote "sing-box 1.11.0 中的更改"

    :material-plus: [server_ports](#server_ports)  
    :material-plus: [hop_interval](#hop_interval)

### 结构

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

  ... // QUIC 字段

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

  ... // 拨号字段
}
```

!!! note ""

    当内容只有一项时，可以忽略 JSON 数组 [] 标签

!!! warning "与官方 Hysteria2 的区别"

    官方程序支持一种名为 **userpass** 的验证方式，
    本质上是将用户名与密码的组合 `<username>:<password>` 作为实际上的密码，而 sing-box 不提供此别名。
    要将 sing-box 与官方程序一起使用， 您需要填写该组合作为实际密码。

### 字段

#### server

==必填==

服务器地址。

与 `realm` 冲突。

#### server_port

==必填==

服务器端口。

如果设置了 `server_ports`，则忽略此项。

与 `realm` 冲突。

#### server_ports

!!! question "自 sing-box 1.11.0 起"

服务器端口范围列表。

与 `server_port` 和 `realm` 冲突。

#### hop_interval

!!! question "自 sing-box 1.11.0 起"

端口跳跃间隔。

默认使用 `30s`。

#### hop_interval_max

!!! question "自 sing-box 1.14.0 起"

最大端口跳跃间隔，用于随机化。

如果设置，实际跳跃间隔将在 `hop_interval` 和 `hop_interval_max` 之间随机选择。

#### up_mbps, down_mbps

最大带宽。

如果为空，将使用 BBR 拥塞控制算法而不是 Hysteria CC。

#### obfs.type

QUIC 流量混淆器类型，可选 `salamander` `gecko`。

如果为空则禁用。

#### obfs.password

QUIC 流量混淆器密码。

#### obfs.min_packet_size

!!! question "自 sing-box 1.14.0 起"

最小线上数据包大小（字节）。仅限 Gecko。

默认使用 `512`。

#### obfs.max_packet_size

!!! question "自 sing-box 1.14.0 起"

最大线上数据包大小（字节）。仅限 Gecko。

默认使用 `1200`。

#### password

认证密码。

#### network

启用的网络协议。

`tcp` 或 `udp`。

默认所有。

#### tls

==必填==

TLS 配置, 参阅 [TLS](/zh/configuration/shared/tls/#出站)。

### QUIC 字段

参阅 [QUIC 字段](/zh/configuration/shared/quic/) 了解详情。

#### bbr_profile

!!! question "自 sing-box 1.14.0 起"

BBR 拥塞控制算法配置，可选 `conservative` `standard` `aggressive`。

默认使用 `standard`。

#### brutal_debug

启用 Hysteria Brutal CC 的调试信息日志记录。

#### disable_chrome_parrot

!!! question "自 sing-box 1.14.0 起"

禁用 Chrome QUIC 指纹模仿。

如果没有禁用，客户端的 QUIC 握手将被构造为模仿 Chrome，使 Hysteria 流量更难通过握手指纹识别。

为了与 Chrome 一致，客户端使用 Chrome 自己的 QUIC 参数，其覆盖部分设置：
`idle_timeout` 固定为 30 秒，`max_concurrent_streams` 与 `initial_packet_size` 被替换为 Chrome 的值，
接收窗口从 Chrome 的初始值开始，再增长到配置的最大值。

!!! warning ""

    Chrome 不声明支持 Ed25519，因此使用 Ed25519 证书的服务端将无法完成握手。
    请改用 ECDSA 或 RSA 证书。

#### realm

!!! question "自 sing-box 1.14.0 起"

通过 Hysteria Realm 会合服务连接 Hysteria2 服务器。

与 `server`、`server_port` 和 `server_ports` 冲突。

TLS SNI 默认使用 `server_url` 中的主机名。需设置 `tls.server_name` 以匹配 Hysteria2 服务器证书覆盖的名字。

会合服务参阅 [Hysteria Realm](/zh/configuration/service/hysteria-realm/)。

#### realm.server_url

==必填==

Realm 会合服务 URL。

#### realm.token

Realm 的 Bearer 令牌，需与 realm 上配置的 `users[].token` 之一匹配。

#### realm.realm_id

==必填==

目标 Hysteria2 服务器注册时使用的相同槽位标识符。

#### realm.stun_servers

==必填==

用于发现本客户端公网地址的 STUN 服务器列表（`host` 或 `host:port`）。

域名通过 [拨号字段](/zh/configuration/shared/dial/) 中的 [`domain_resolver`](/zh/configuration/shared/dial/#domain_resolver) 解析。

#### realm.ip_version

将 realm 连接（STUN、打洞与最终的 QUIC 路径）限制为单一 IP 版本。

`4` 或 `6`。默认使用两者。

#### realm.port_mapping

通过 UPnP 或 NAT-PMP 在本地网关上维护 UDP 端口映射。

可在支持的网关后提升打洞成功率。

需要 IPv4：与 `"ip_version": 6` 冲突。

#### realm.port_mapping.enabled

启用端口映射。

#### realm.port_mapping.timeout

网关发现与映射操作的超时。

默认使用 `10s`。

#### realm.port_mapping.lifetime

映射的租约时长。

默认使用 `10m`。

#### realm.http_client

与 realm 通信使用的 HTTP 客户端。

参阅 [HTTP 客户端](/zh/configuration/shared/http-client/) 了解详情。

### UDP2Raw 字段

!!! question "自 sing-box 1.15.0"

把 QUIC 数据报装进一条"看起来是 TCP"的通道，从而绕开 UDP 阻断、UDP QoS 与 QUIC 指纹识别。
两端必须同时启用，且 `mode` 与 `auth` 一致。

`faketcp` 直接在线上构造 TCP 段：本层不重传、不做拥塞控制，QUIC 的行为与跑在 UDP 上完全一致。
`tcp` 把数据报分帧塞进真实 TCP 连接，不需要特权，但会承受 TCP-over-TCP 的队头阻塞。

`udp2raw` 与 `server_ports`、`hop_interval`、`hop_interval_max`、`realm` 冲突。

#### udp2raw.mode

承载模式，可选 `auto` `faketcp` `tcp`。

默认 `auto`：有裸套接字权限时优先 `faketcp`，平台或权限不允许时回退 `tcp`。

#### udp2raw.port

承载层 TCP 端口，`0` 表示复用 `server_port`。

#### udp2raw.auth

可选的预共享串，用 HMAC 时间戳做准入。它不是加密，机密性仍由 QUIC/TLS 提供。

#### udp2raw.mtu

承载层必须容纳的路径 MTU，默认 `1500`。PPPoE（1492）或隧道链路上请填真实值。

未显式设置 `initial_packet_size` 时，它由该值推导（钳制在 1200..1280），
保证 QUIC 的首包不会超过路径 MTU。

#### udp2raw.keep_alive

保活包间隔，默认 `15s`。

#### udp2raw.idle_timeout

超过该空闲时间判定会话死亡，默认 `45s`。

#### udp2raw.handshake_timeout

承载层握手允许的总时长，默认 `8s`。

#### udp2raw.camouflage

`none` 或 `tls`，默认 `none`。

`tls` 会把帧装进 TLS 记录并做一次伪 TLS 握手，使流量外观像 HTTPS。
它只做外观：证书是自签的，真实 TLS 客户端无法完成握手。

#### udp2raw.sni

`camouflage: tls` 使用的 SNI，默认为服务器主机名。

#### udp2raw.faketcp

| 字段 | 默认值 | 说明 |
|------|--------|------|
| `src_port` | `0` | 源 TCP 端口，`0` 表示随机 |
| `ttl` | `64` | 写入 IPv4 头的 TTL |
| `mss` | `mtu - 40` | TCP 选项里通告的 MSS |
| `window_scale` | `7` | TCP 选项里通告的窗口缩放 |
| `gro_split` | `auto` | 按 MSS 拆分 GRO 聚合包 |
| `raw_interface` | `""` | 抓包绑定的网卡，空表示全部 |

#### udp2raw.tcp

| 字段 | 默认值 | 说明 |
|------|--------|------|
| `dial_timeout` | `8s` | 拨号承载层的超时 |

### 拨号字段

参阅 [拨号字段](/zh/configuration/shared/dial/)。
