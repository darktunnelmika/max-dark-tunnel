// Package config holds the on-disk description of one tunnel.
package config

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
)

// Transports, mirroring the installer menu.
const (
	TransportTCP = "tcp" // TCP Forward: multiplexed streams over one encrypted carrier
	TransportTun = "tun" // layer-3 tun device over a selectable carrier
	TransportDNS = "dns" // tun over DNS-shaped UDP
	TransportSSH = "ssh" // TCP Forward over an embedded SSH session
)

// Carriers for TransportTun.
const (
	CarrierMDTP = "mdtp" // raw IP protocol number (GRE/ESP/any)
	CarrierICMP = "icmp"
	CarrierTCP  = "tcp"
	CarrierUDP  = "udp"
)

const (
	RoleIran   = "iran"
	RoleKharej = "kharej"

	DirReverse = "reverse" // iran listens, kharej dials
	DirDirect  = "direct"  // kharej listens, iran dials
)

type Config struct {
	Name      string `json:"name"`
	Role      string `json:"role"`
	Transport string `json:"transport"`
	Carrier   string `json:"carrier,omitempty"`
	Direction string `json:"direction,omitempty"`

	Port     int    `json:"port,omitempty"`      // carrier port (tcp/ssh/dns, tun over tcp/udp)
	IranIP   string `json:"iran_ip,omitempty"`   // public IP of the iran server
	KharejIP string `json:"kharej_ip,omitempty"` // public IP of the kharej server
	BindIP   string `json:"bind_ip,omitempty"`   // local bind address, default 0.0.0.0
	PSK      string `json:"psk"`

	Proto    int `json:"proto,omitempty"`     // mdtp: IP protocol number
	ICMPType int `json:"icmp_type,omitempty"` // icmp: type sent by iran (kharej sends ICMPReply)
	ICMPCode int `json:"icmp_code,omitempty"`
	ICMPRply int `json:"icmp_reply,omitempty"` // icmp: type sent by kharej

	Subnet int    `json:"subnet,omitempty"` // tun: 10.20.<subnet>.1/2
	TunDev string `json:"tun_dev,omitempty"`
	MTU    int    `json:"mtu,omitempty"`

	DNSDomain string `json:"dns_domain,omitempty"`
	Mux       int    `json:"mux,omitempty"` // parallel carrier connections (tcp/ssh)

	// Iran only: user-facing ports. "443" or "443>8443" or "443>1.2.3.4:80".
	TCPPorts string `json:"tcp_ports,omitempty"`
	UDPPorts string `json:"udp_ports,omitempty"`

	LogFile    string `json:"log_file,omitempty"`
	StatusFile string `json:"status_file,omitempty"`
}

var nameRe = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,24}$`)

func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	c.Defaults()
	return &c, c.Validate()
}

func (c *Config) Save(path string) error {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false) // keep "443>8443" readable for the shell manager
	enc.SetIndent("", "  ")
	if err := enc.Encode(c); err != nil {
		return err
	}
	return os.WriteFile(path, buf.Bytes(), 0o600)
}

// Defaults fills every field the installer may leave empty.
func (c *Config) Defaults() {
	if c.BindIP == "" {
		c.BindIP = "0.0.0.0"
	}
	if c.Direction == "" {
		c.Direction = DirReverse
		if c.Transport == TransportSSH {
			c.Direction = DirDirect // iran logs in to kharej, like real ssh
		}
	}
	switch c.Transport {
	case TransportTCP:
		def(&c.Port, 443)
		def(&c.Mux, 4)
	case TransportSSH:
		def(&c.Port, 2020)
		def(&c.Mux, 2)
	case TransportDNS:
		def(&c.Port, 53)
		if c.DNSDomain == "" {
			c.DNSDomain = "cdn.example.com"
		}
		def(&c.MTU, 1200)
	case TransportTun:
		if c.Carrier == "" {
			c.Carrier = CarrierMDTP
		}
		switch c.Carrier {
		case CarrierTCP, CarrierUDP:
			def(&c.Port, 443)
		case CarrierMDTP:
			def(&c.Proto, 47)
		case CarrierICMP:
			if c.ICMPType == 0 && c.ICMPRply == 0 {
				c.ICMPType, c.ICMPRply = 8, 0
			}
		}
	}
	if c.IsTun() {
		def(&c.MTU, 1380)
		if c.TunDev == "" {
			c.TunDev = "mdt" + strconv.Itoa(c.Subnet)
		}
	}
	if c.LogFile == "" && c.Name != "" {
		c.LogFile = "/var/log/max-dark-tunnel/" + c.Name + ".log"
	}
	if c.StatusFile == "" && c.Name != "" {
		c.StatusFile = "/run/max-dark-tunnel/" + c.Name + ".json"
	}
}

func def(p *int, v int) {
	if *p == 0 {
		*p = v
	}
}

func (c *Config) IsTun() bool  { return c.Transport == TransportTun || c.Transport == TransportDNS }
func (c *Config) IsIran() bool { return c.Role == RoleIran }

// PeerIP is the public address of the other side.
func (c *Config) PeerIP() string {
	if c.IsIran() {
		return c.KharejIP
	}
	return c.IranIP
}

// Listens reports whether this side binds the carrier port.
func (c *Config) Listens() bool {
	if c.Transport == TransportDNS {
		return !c.IsIran() // kharej is the "DNS server"
	}
	if c.Direction == DirReverse {
		return c.IsIran()
	}
	return !c.IsIran()
}

// TunIPs returns local and peer tunnel addresses.
func (c *Config) TunIPs() (local, peer string) {
	a := fmt.Sprintf("10.20.%d.1", c.Subnet)
	b := fmt.Sprintf("10.20.%d.2", c.Subnet)
	if c.IsIran() {
		return a, b
	}
	return b, a
}

func (c *Config) Validate() error {
	if !nameRe.MatchString(c.Name) {
		return errors.New("name: 1-24 chars of a-z A-Z 0-9 _ -")
	}
	if c.Role != RoleIran && c.Role != RoleKharej {
		return errors.New("role must be iran or kharej")
	}
	if len(c.PSK) < 16 {
		return errors.New("psk too short")
	}
	switch c.Transport {
	case TransportTCP, TransportSSH, TransportDNS:
	case TransportTun:
		switch c.Carrier {
		case CarrierMDTP, CarrierICMP, CarrierTCP, CarrierUDP:
		default:
			return fmt.Errorf("unknown carrier %q", c.Carrier)
		}
	default:
		return fmt.Errorf("unknown transport %q", c.Transport)
	}
	if c.Direction != DirReverse && c.Direction != DirDirect {
		return errors.New("direction must be reverse or direct")
	}
	if c.Port < 0 || c.Port > 65535 {
		return errors.New("bad port")
	}
	if c.Proto < 0 || c.Proto > 255 {
		return errors.New("proto must be 0-255")
	}
	if c.Subnet < 0 || c.Subnet > 255 {
		return errors.New("subnet must be 0-255")
	}
	if c.MTU != 0 && (c.MTU < 576 || c.MTU > 9000) {
		return errors.New("mtu must be 576-9000")
	}
	// The side that dials, and both sides of a raw/icmp/dns link, need the peer address.
	needPeer := !c.Listens()
	if c.Transport == TransportTun && (c.Carrier == CarrierMDTP || c.Carrier == CarrierICMP) {
		needPeer = true
	}
	if needPeer && net.ParseIP(c.PeerIP()) == nil {
		return fmt.Errorf("peer ip missing or invalid (%q)", c.PeerIP())
	}
	if c.IsIran() {
		if _, err := ParsePorts(c.TCPPorts); err != nil {
			return fmt.Errorf("tcp_ports: %w", err)
		}
		if _, err := ParsePorts(c.UDPPorts); err != nil {
			return fmt.Errorf("udp_ports: %w", err)
		}
	}
	return nil
}

// PortMap is one user-facing port on iran and where it lands on kharej.
type PortMap struct {
	Listen int
	Target string // "8443" (kharej loopback / tun peer) or "host:port"
}

func ParsePorts(s string) ([]PortMap, error) {
	var out []PortMap
	for _, f := range strings.Split(s, ",") {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		l, t, _ := strings.Cut(f, ">")
		lp, err := strconv.Atoi(l)
		if err != nil || lp < 1 || lp > 65535 {
			return nil, fmt.Errorf("bad port %q", f)
		}
		if t == "" {
			t = l
		}
		if p, err := strconv.Atoi(t); err == nil {
			if p < 1 || p > 65535 {
				return nil, fmt.Errorf("bad target %q", f)
			}
		} else if _, _, err := net.SplitHostPort(t); err != nil {
			return nil, fmt.Errorf("bad target %q", f)
		}
		out = append(out, PortMap{Listen: lp, Target: t})
	}
	return out, nil
}

func NewPSK() string {
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
