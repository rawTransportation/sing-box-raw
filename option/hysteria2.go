package option

import (
	"net/url"
	"reflect"
	"slices"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/schema"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/json/badjson"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"
)

type Hysteria2InboundOptions struct {
	ListenOptions
	UpMbps                int             `json:"up_mbps,omitempty"`
	DownMbps              int             `json:"down_mbps,omitempty"`
	Obfs                  *Hysteria2Obfs  `json:"obfs,omitempty"`
	Users                 []Hysteria2User `json:"users,omitempty"`
	IgnoreClientBandwidth bool            `json:"ignore_client_bandwidth,omitempty"`
	InboundTLSOptionsContainer
	QUICOptions
	Masquerade  *Hysteria2Masquerade            `json:"masquerade,omitempty"`
	BBRProfile  string                          `json:"bbr_profile,omitempty" enum:"standard,conservative,aggressive"`
	BrutalDebug bool                            `json:"brutal_debug,omitempty"`
	Realm       *Hysteria2InboundRealm          `json:"realm,omitempty"`
	UDP2Raw     *Hysteria2UDP2RawInboundOptions `json:"udp2raw,omitempty"`
}

// Hysteria2UDP2RawFakeTCPOptions configures the fake-TCP carrier: TCP segments
// are crafted on the wire while retransmission and congestion control are left
// to QUIC.
type Hysteria2UDP2RawFakeTCPOptions struct {
	SrcPort      uint16 `json:"src_port,omitempty"`
	TTL          uint8  `json:"ttl,omitempty"`
	MSS          uint16 `json:"mss,omitempty"`
	WindowScale  uint8  `json:"window_scale,omitempty"`
	GROSplit     string `json:"gro_split,omitempty" enum:"auto,on,off"`
	RawInterface string `json:"raw_interface,omitempty"`
}

// Hysteria2UDP2RawTCPOptions configures the real-TCP carrier, the fallback for
// platforms without raw socket support.
type Hysteria2UDP2RawTCPOptions struct {
	DialTimeout badoption.Duration `json:"dial_timeout,omitempty"`
	Listen      string             `json:"listen,omitempty"`
}

// Hysteria2UDP2RawOptions is the shared part of the udp2raw transport, which
// carries QUIC datagrams inside a channel that looks like a TCP flow.
type Hysteria2UDP2RawOptions struct {
	Mode             string                         `json:"mode,omitempty" enum:"auto,faketcp,tcp"`
	Port             uint16                         `json:"port,omitempty"`
	Auth             string                         `json:"auth,omitempty"`
	MTU              int                            `json:"mtu,omitempty"`
	KeepAlive        badoption.Duration             `json:"keep_alive,omitempty"`
	IdleTimeout      badoption.Duration             `json:"idle_timeout,omitempty"`
	HandshakeTimeout badoption.Duration             `json:"handshake_timeout,omitempty"`
	Camouflage       string                         `json:"camouflage,omitempty" enum:"none,tls"`
	SNI              string                         `json:"sni,omitempty"`
	FakeTCP          Hysteria2UDP2RawFakeTCPOptions `json:"faketcp,omitempty"`
	TCP              Hysteria2UDP2RawTCPOptions     `json:"tcp,omitempty"`
}

// Hysteria2UDP2RawInboundOptions adds the server-only knobs.
type Hysteria2UDP2RawInboundOptions struct {
	Hysteria2UDP2RawOptions
	AutoFirewall     bool `json:"auto_firewall,omitempty"`
	MaxSessions      int  `json:"max_sessions,omitempty"`
	MaxSessionsPerIP int  `json:"max_sessions_per_ip,omitempty"`
}

type Hysteria2Realm struct {
	ServerURL   string                     `json:"server_url"`
	Token       string                     `json:"token,omitempty"`
	RealmID     string                     `json:"realm_id"`
	STUNServers LegacyListable[string]     `json:"stun_servers"`
	IPVersion   int                        `json:"ip_version,omitempty" enum:"0,4,6"`
	PortMapping *Hysteria2RealmPortMapping `json:"port_mapping,omitempty"`
	HTTPClient  *HTTPClientOptions         `json:"http_client,omitempty"`
}

func (r Hysteria2Realm) STUNServersIsDomain() bool {
	return slices.ContainsFunc(r.STUNServers, func(server string) bool {
		return M.ParseSocksaddr(server).IsDomain()
	})
}

type Hysteria2RealmPortMapping struct {
	Enabled  bool               `json:"enabled,omitempty"`
	Timeout  badoption.Duration `json:"timeout,omitempty"`
	Lifetime badoption.Duration `json:"lifetime,omitempty"`
}

type Hysteria2InboundRealm struct {
	Hysteria2Realm
	STUNDomainResolver *DomainResolveOptions `json:"stun_domain_resolver,omitempty"`
}

type Hysteria2ObfsGecko struct {
	MinPacketSize int `json:"min_packet_size,omitempty"`
	MaxPacketSize int `json:"max_packet_size,omitempty"`
}

type _Hysteria2Obfs struct {
	Type         string             `json:"type,omitempty" enum:"salamander,gecko"`
	Password     string             `json:"password,omitempty"`
	GeckoOptions Hysteria2ObfsGecko `json:"-"`
}

type Hysteria2Obfs _Hysteria2Obfs

func (o Hysteria2Obfs) MarshalJSON() ([]byte, error) {
	var v any
	switch o.Type {
	case C.Hysteria2ObfsTypeSalamander:
	case C.Hysteria2ObfsTypeGecko:
		v = o.GeckoOptions
	default:
		return nil, E.New("unknown obfs type: ", o.Type)
	}
	return badjson.MarshallObjects(_Hysteria2Obfs(o), v)
}

func (o *Hysteria2Obfs) UnmarshalJSON(bytes []byte) error {
	err := json.Unmarshal(bytes, (*_Hysteria2Obfs)(o))
	if err != nil {
		return err
	}
	var v any
	switch o.Type {
	case C.Hysteria2ObfsTypeSalamander:
	case C.Hysteria2ObfsTypeGecko:
		v = &o.GeckoOptions
	default:
		return E.New("unknown obfs type: ", o.Type)
	}
	if v == nil {
		return nil
	}
	return badjson.UnmarshallExcluded(bytes, (*_Hysteria2Obfs)(o), v)
}

func (o Hysteria2Obfs) DescribeSchema(builder schema.Builder) (*schema.Node, error) {
	return schema.DiscriminatedUnion(builder, "type", true, []schema.UnionVariant{
		{Value: C.Hysteria2ObfsTypeSalamander},
		{Value: C.Hysteria2ObfsTypeGecko, StructType: reflect.TypeFor[Hysteria2ObfsGecko]()},
	}, func(variant *schema.Node) error {
		variant.Properties.Put("password", schema.StringNode())
		return nil
	})
}

type Hysteria2User struct {
	Name     string `json:"name,omitempty"`
	Password string `json:"password,omitempty"`
}

type _Hysteria2Masquerade struct {
	Type          string                    `json:"type,omitempty" enum:"file,proxy,string"`
	FileOptions   Hysteria2MasqueradeFile   `json:"-"`
	ProxyOptions  Hysteria2MasqueradeProxy  `json:"-"`
	StringOptions Hysteria2MasqueradeString `json:"-"`
}

type Hysteria2Masquerade _Hysteria2Masquerade

func (m Hysteria2Masquerade) MarshalJSON() ([]byte, error) {
	var v any
	switch m.Type {
	case C.Hysterai2MasqueradeTypeFile:
		v = m.FileOptions
	case C.Hysterai2MasqueradeTypeProxy:
		v = m.ProxyOptions
	case C.Hysterai2MasqueradeTypeString:
		v = m.StringOptions
	default:
		return nil, E.New("unknown masquerade type: ", m.Type)
	}
	return badjson.MarshallObjects(_Hysteria2Masquerade(m), v)
}

func (m *Hysteria2Masquerade) UnmarshalJSON(bytes []byte) error {
	var urlString string
	err := json.Unmarshal(bytes, &urlString)
	if err == nil {
		masqueradeURL, err := url.Parse(urlString)
		if err != nil {
			return E.Cause(err, "invalid masquerade URL")
		}
		switch masqueradeURL.Scheme {
		case "file":
			m.Type = C.Hysterai2MasqueradeTypeFile
			m.FileOptions.Directory = masqueradeURL.Path
		case "http", "https":
			m.Type = C.Hysterai2MasqueradeTypeProxy
			m.ProxyOptions.URL = urlString
		default:
			return E.New("unknown masquerade URL scheme: ", masqueradeURL.Scheme)
		}
		return nil
	}
	err = json.Unmarshal(bytes, (*_Hysteria2Masquerade)(m))
	if err != nil {
		return err
	}
	var v any
	switch m.Type {
	case C.Hysterai2MasqueradeTypeFile:
		v = &m.FileOptions
	case C.Hysterai2MasqueradeTypeProxy:
		v = &m.ProxyOptions
	case C.Hysterai2MasqueradeTypeString:
		v = &m.StringOptions
	default:
		return E.New("unknown masquerade type: ", m.Type)
	}
	return badjson.UnmarshallExcluded(bytes, (*_Hysteria2Masquerade)(m), v)
}

func (m Hysteria2Masquerade) DescribeSchema(builder schema.Builder) (*schema.Node, error) {
	union, err := schema.DiscriminatedUnion(builder, "type", true, []schema.UnionVariant{
		{Value: C.Hysterai2MasqueradeTypeFile, StructType: reflect.TypeFor[Hysteria2MasqueradeFile]()},
		{Value: C.Hysterai2MasqueradeTypeProxy, StructType: reflect.TypeFor[Hysteria2MasqueradeProxy]()},
		{Value: C.Hysterai2MasqueradeTypeString, StructType: reflect.TypeFor[Hysteria2MasqueradeString]()},
	}, nil)
	if err != nil {
		return nil, err
	}
	return schema.AnyOf(schema.StringNode(), union), nil
}

type Hysteria2MasqueradeFile struct {
	Directory string `json:"directory"`
}

type Hysteria2MasqueradeProxy struct {
	URL         string `json:"url"`
	RewriteHost bool   `json:"rewrite_host,omitempty"`
}

type Hysteria2MasqueradeString struct {
	StatusCode int                  `json:"status_code,omitempty"`
	Headers    badoption.HTTPHeader `json:"headers,omitempty"`
	Content    string               `json:"content"`
}

type Hysteria2OutboundOptions struct {
	DialerOptions
	ServerOptions
	ServerPorts    LegacyListable[string] `json:"server_ports,omitempty"`
	HopInterval    badoption.Duration     `json:"hop_interval,omitempty"`
	HopIntervalMax badoption.Duration     `json:"hop_interval_max,omitempty"`
	UpMbps         int                    `json:"up_mbps,omitempty"`
	DownMbps       int                    `json:"down_mbps,omitempty"`
	Obfs           *Hysteria2Obfs         `json:"obfs,omitempty"`
	Password       string                 `json:"password,omitempty"`
	Network        NetworkList            `json:"network,omitempty"`
	OutboundTLSOptionsContainer
	QUICOptions
	BBRProfile          string                   `json:"bbr_profile,omitempty" enum:"standard,conservative,aggressive"`
	BrutalDebug         bool                     `json:"brutal_debug,omitempty"`
	DisableChromeParrot bool                     `json:"disable_chrome_parrot,omitempty"`
	Realm               *Hysteria2Realm          `json:"realm,omitempty"`
	UDP2Raw             *Hysteria2UDP2RawOptions `json:"udp2raw,omitempty"`
}

type HysteriaRealmUser struct {
	Name      string `json:"name"`
	Token     string `json:"token"`
	MaxRealms int    `json:"max_realms,omitempty"`
}

type HysteriaRealmServiceOptions struct {
	ListenOptions
	InboundTLSOptionsContainer
	HTTP2Options
	Users []HysteriaRealmUser `json:"users"`
}
