---
icon: material/alert-decagram
---

!!! quote "sing-box 1.14.0 中的更改"

    :material-plus: [bbr_profile](#bbr_profile)  
    :material-plus: [realm](#realm)  
    :material-alert: [obfs](#obfstype)

!!! quote "sing-box 1.11.0 中的更改"

    :material-alert: [masquerade](#masquerade)  
    :material-alert: [ignore_client_bandwidth](#ignore_client_bandwidth)

### 结构

```json
{
  "type": "hysteria2",
  "tag": "hy2-in",
  
  ... // 监听字段

  "up_mbps": 100,
  "down_mbps": 100,
  "obfs": {
    "type": "salamander",
    "password": "cry_me_a_r1ver"
  },
  "users": [
    {
      "name": "tobyxdd",
      "password": "goofy_ahh_password"
    }
  ],
  "ignore_client_bandwidth": false,
  "tls": {},
  "udp2raw": {
    "mode": "auto",
    "port": 0,
    "auth": "",
    "mtu": 1500,
    "keep_alive": "15s",
    "idle_timeout": "60s",
    "handshake_timeout": "8s",
    "camouflage": "none",
    "sni": "",
    "faketcp": {
      "ttl": 64,
      "mss": 1460,
      "window_scale": 7,
      "gro_split": "auto",
      "raw_interface": ""
    },
    "tcp": {
      "listen": ""
    },
    "auto_firewall": false,
    "max_sessions": 8192,
    "max_sessions_per_ip": 256
  },

  ... // QUIC 字段

  "masquerade": "", // 或 {}
  "bbr_profile": "",
  "brutal_debug": false,
  "realm": {
    "server_url": "https://realm.example.com",
    "token": "",
    "realm_id": "",
    "stun_servers": [],
    "stun_domain_resolver": "", // 或 {}
    "ip_version": 0,
    "port_mapping": {
      "enabled": false,
      "timeout": "",
      "lifetime": ""
    },
    "http_client": {}
  }
}
```

!!! warning "与官方 Hysteria2 的区别"

    官方程序支持一种名为 **userpass** 的验证方式，
    本质上是将用户名与密码的组合 `<username>:<password>` 作为实际上的密码，而 sing-box 不提供此别名。
    要将 sing-box 与官方程序一起使用， 您需要填写该组合作为实际密码。

### 监听字段

参阅 [监听字段](/zh/configuration/shared/listen/)。

### 字段

#### up_mbps, down_mbps

支持的速率，默认不限制。

与 `ignore_client_bandwidth` 冲突。

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

#### users

Hysteria 用户

#### users.password

认证密码。

#### ignore_client_bandwidth

*当 `up_mbps` 和 `down_mbps` 未设定时*:

命令客户端使用 BBR 拥塞控制算法而不是 Hysteria CC。

*当 `up_mbps` 和 `down_mbps` 已设定时*:

禁止客户端使用 BBR 拥塞控制算法。

#### tls

==必填==

TLS 配置, 参阅 [TLS](/zh/configuration/shared/tls/#入站)。

### UDP2Raw 字段

!!! question "自 sing-box 1.15.0"

从一条"看起来是 TCP"的通道接收 QUIC 数据报，从而绕开 UDP 阻断、UDP QoS 与 QUIC 指纹识别。
两端必须同时启用，且 `mode` 与 `auth` 一致。

`faketcp` 直接在线上构造 TCP 段：本层不重传、不做拥塞控制，QUIC 的行为与跑在 UDP 上完全一致。
`tcp` 把数据报分帧塞进真实 TCP 连接，不需要特权，但会承受 TCP-over-TCP 的队头阻塞。

`udp2raw` 与 `realm` 冲突。它替换本入站的 UDP 套接字：`listen` 与 `listen_port` 只描述逻辑端点，
承载层实际监听在 `udp2raw.port`。

#### udp2raw.mode

承载模式，可选 `auto` `faketcp` `tcp`。

默认 `auto`：有裸套接字权限时优先 `faketcp`，平台或权限不允许时回退 `tcp`。

#### udp2raw.port

承载层 TCP 端口，`0` 表示复用 `listen_port`。

`faketcp` 会在线上占用该 TCP 端口，因此不能有其他程序监听它，还需要抑制内核对它的响应，
见 `auto_firewall`。

#### udp2raw.auth

可选的预共享串，用 HMAC 时间戳做准入。它不是加密，机密性仍由 QUIC/TLS 提供。

#### udp2raw.mtu

承载层必须容纳的路径 MTU，默认 `1500`。PPPoE（1492）或隧道链路上请填真实值。

未显式设置 `initial_packet_size` 时，它由该值推导（钳制在 1200..1280），
保证 QUIC 的首包不会超过路径 MTU。

#### udp2raw.keep_alive

保活包间隔，默认 `15s`。

#### udp2raw.idle_timeout

超过该空闲时间回收会话，默认 `60s`。

#### udp2raw.handshake_timeout

承载层握手允许的总时长，默认 `8s`。

#### udp2raw.camouflage

`none` 或 `tls`，默认 `none`。

`tls` 会把帧装进 TLS 记录并做一次伪 TLS 握手，使流量外观像 HTTPS。
它只做外观：证书是自签的，真实 TLS 客户端无法完成握手。

#### udp2raw.sni

`camouflage: tls` 使用的 SNI。

#### udp2raw.faketcp

| 字段 | 默认值 | 说明 |
|------|--------|------|
| `ttl` | `64` | 写入 IPv4 头的 TTL |
| `mss` | `mtu - 40` | TCP 选项里通告的 MSS |
| `window_scale` | `7` | TCP 选项里通告的窗口缩放 |
| `gro_split` | `auto` | 按 MSS 拆分 GRO 聚合包 |
| `raw_interface` | `""` | 抓包绑定的网卡，空表示全部 |

`faketcp` 在 Linux 上需要 `CAP_NET_RAW`，在 Windows 上需要可执行文件旁有
`WinDivert.dll` 与 `WinDivert64.sys`。它只支持 IPv4。

#### udp2raw.tcp

| 字段 | 默认值 | 说明 |
|------|--------|------|
| `listen` | `:<udp2raw.port>` | 承载层监听地址 |

#### udp2raw.auto_firewall

用 `nft` 或 `iptables` 自动安装并清理 `faketcp` 所需的内核 RST 抑制规则。
需要 root，仅 Linux，默认关闭。

#### udp2raw.max_sessions

最大并发会话数，默认 `8192`。

#### udp2raw.max_sessions_per_ip

单个源 IP 的最大并发会话数，默认 `256`。

### QUIC 字段

参阅 [QUIC 字段](/zh/configuration/shared/quic/) 了解详情。

#### masquerade

HTTP3 服务器认证失败时的行为 （URL 字符串配置）。

| Scheme       | 示例                      | 描述      |
|--------------|-------------------------|---------|
| `file`       | `file:///var/www`       | 作为文件服务器 |
| `http/https` | `http://127.0.0.1:8080` | 作为反向代理  |

如果 masquerade 未配置，则返回 404 页。

与 `masquerade.type` 冲突。

#### masquerade.type

HTTP3 服务器认证失败时的行为 （对象配置）。

| Type     | 描述      | 字段                                  |
|----------|---------|-------------------------------------|
| `file`   | 作为文件服务器 | `directory`                         |
| `proxy`  | 作为反向代理  | `url`, `rewrite_host`               |
| `string` | 返回固定响应  | `status_code`, `headers`, `content` |

如果 masquerade 未配置，则返回 404 页。

与 `masquerade` 冲突。

#### masquerade.directory

文件服务器根目录。

#### masquerade.url

反向代理目标 URL。

#### masquerade.rewrite_host

重写请求头中的 Host 字段到目标 URL。

#### masquerade.status_code

固定响应状态码。

#### masquerade.headers

固定响应头。

#### masquerade.content

固定响应内容。

#### bbr_profile

!!! question "自 sing-box 1.14.0 起"

BBR 拥塞控制算法配置，可选 `conservative` `standard` `aggressive`。

默认使用 `standard`。

#### brutal_debug

启用 Hysteria Brutal CC 的调试信息日志记录。

#### realm

!!! question "自 sing-box 1.14.0 起"

将此入站注册到 Hysteria Realm 会合服务，以启用 NAT 穿透。

会合服务参阅 [Hysteria Realm](/zh/configuration/service/hysteria-realm/)。

#### realm.server_url

==必填==

Realm 会合服务 URL。

#### realm.token

Realm 的 Bearer 令牌，需与 realm 上配置的 `users[].token` 之一匹配。

#### realm.realm_id

==必填==

Realm 上的槽位标识符。

1–64 字符，需匹配 `^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$`。

出站需使用相同的 `realm_id` 才能找到本服务器。

#### realm.stun_servers

==必填==

用于发现公网地址的 STUN 服务器列表（`host` 或 `host:port`）。

#### realm.stun_domain_resolver

用于解析 STUN 服务器域名的域名解析器。

此选项的格式与 [路由 DNS 规则动作](/zh/configuration/dns/rule_action/#route) 相同，但不包含 `action` 字段。

若直接将此选项设置为字符串，则等同于设置该选项的 `server` 字段。

如果为空，则使用默认域名解析器。

#### realm.ip_version

将 realm 连接（STUN、打洞与最终的 QUIC 路径）限制为单一 IP 版本。

`4` 或 `6`。默认使用两者。

`listen` 地址必须与所选版本兼容。

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
