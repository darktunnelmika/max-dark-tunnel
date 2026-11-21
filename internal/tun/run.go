package tun

import (
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/darktunnelmika/max-dark-tunnel/internal/config"
	"github.com/darktunnelmika/max-dark-tunnel/internal/crypt"
	"github.com/darktunnelmika/max-dark-tunnel/internal/fwd"
	"github.com/darktunnelmika/max-dark-tunnel/internal/status"
)

const (
	pktKeepalive = 0
	pktData      = 1

	// Bytes of tunnel data per DNS query; 0 sends each packet as one query.
	// Splitting keeps queries small, but networks that police DNS count
	// queries rather than bytes (measured on an Iranian DC line: ~12 queries
	// per burst, any size), so more queries only reach that limit sooner.
	dnsQueryPayload = 0
)

func buildLink(ctx context.Context, cfg *config.Config) (Link, error) {
	peer := cfg.PeerIP()
	if cfg.Transport == config.TransportDNS {
		l, err := newUDP(cfg.BindIP, cfg.Port, peer, !cfg.IsIran())
		if err != nil {
			return nil, err
		}
		l.wrap = dnsWrapper(cfg.DNSDomain, cfg.IsIran())
		l.unwrap = dnsUnwrapper(cfg.IsIran())
		l.frag = true
		if cfg.IsIran() {
			l.fragMax = dnsQueryPayload // queries stay small; responses go whole
		}
		return l, nil
	}
	switch cfg.Carrier {
	case config.CarrierMDTP:
		if cfg.SpoofSrc != "" && cfg.SpoofDst != "" {
			return newSpoofRaw(cfg.Proto, peer, cfg.SpoofSrc, cfg.SpoofDst, cfg.PSK)
		}
		return newRaw(cfg.BindIP, cfg.Proto, peer, cfg.PSK)
	case config.CarrierICMP:
		id := binary.BigEndian.Uint16(crypt.Derive(cfg.PSK, nil, "icmp id", 2))
		send, recv := cfg.ICMPType, cfg.ICMPRply
		if !cfg.IsIran() {
			send, recv = recv, send
		}
		return newICMP(cfg.BindIP, peer, send, recv, cfg.ICMPCode, id, !cfg.IsIran())
	case config.CarrierUDP:
		return newUDP(cfg.BindIP, cfg.Port, peer, cfg.Listens())
	case config.CarrierTCP:
		return newTCP(ctx, cfg.BindIP, cfg.Port, peer, cfg.PSK, cfg.CC, cfg.Listens())
	}
	return nil, fmt.Errorf("unknown carrier %q", cfg.Carrier)
}

// Run brings up the tun device and the link, and blocks.
func Run(ctx context.Context, cfg *config.Config, st *status.Tracker) error {
	local, peerTun := cfg.TunIPs()
	dev, err := Open(cfg.TunDev, local, cfg.MTU)
	if err != nil {
		return err
	}
	defer dev.Close()
	log.Printf("tun %s up: %s <-> %s mtu %d", cfg.TunDev, local, peerTun, cfg.MTU)

	link, err := buildLink(ctx, cfg)
	if err != nil {
		return fmt.Errorf("carrier: %w", err)
	}
	defer link.Close()
	desc := cfg.Transport
	if cfg.Transport == config.TransportTun {
		desc += "/" + cfg.Carrier
	}
	log.Printf("carrier %s ready (peer %s)", desc, cfg.PeerIP())

	pk := crypt.NewPacket(cfg.PSK, cfg.IsIran())
	var lastRx atomic.Int64
	var peerSeen atomic.Value
	peerSeen.Store(cfg.PeerIP())

	loss := &lossMeter{}

	// tun -> link
	go func() {
		buf := make([]byte, 1+65535)
		out := make([]byte, 0, 65535+crypt.PacketOverhead+1)
		for {
			n, err := dev.Read(buf[1:])
			if err != nil {
				log.Printf("tun read: %v", err)
				return
			}
			buf[0] = pktData
			out = pk.Seal(out[:0], buf[:1+n])
			if link.Send(out) == nil {
				st.AddTx(n)
			}
		}
	}()

	// link -> tun
	go func() {
		buf := make([]byte, 65535+64)
		pt := make([]byte, 0, 65535)
		for {
			n, from, err := link.Recv(buf)
			if err != nil {
				if ctx.Err() == nil {
					log.Printf("carrier read: %v", err)
				}
				return
			}
			p, err := pk.Open(pt[:0], buf[:n])
			if err != nil || len(p) == 0 {
				continue
			}
			link.Confirm(from)
			lastRx.Store(time.Now().UnixNano())
			if from != nil {
				if h, _, e := net.SplitHostPort(from.String()); e == nil {
					peerSeen.Store(h)
				} else {
					peerSeen.Store(from.String())
				}
			}
			if p[0] == pktKeepalive && len(p) >= 5 {
				loss.seen(binary.BigEndian.Uint32(p[1:]), st)
			}
			if p[0] == pktData && len(p) > 1 {
				if _, err := dev.Write(p[1:]); err == nil {
					st.AddRx(len(p) - 1)
				}
			}
		}
	}()

	if cfg.IsIran() {
		if err := startTunForwarders(ctx, cfg, peerTun, st); err != nil {
			return err
		}
	}

	var ka []byte
	var kaSeq uint32
	kaMsg := make([]byte, 5)
	t := time.NewTicker(3 * time.Second)
	defer t.Stop()
	for {
		// Numbered, so the peer can tell how many never arrived.
		kaSeq++
		kaMsg[0] = pktKeepalive
		binary.BigEndian.PutUint32(kaMsg[1:], kaSeq)
		ka = pk.Seal(ka[:0], kaMsg)
		_ = link.Send(ka)
		live := time.Since(time.Unix(0, lastRx.Load())) < 12*time.Second
		n := 0
		if live {
			n = 1
		}
		if !live {
			loss.reset()
		}
		st.Set(live, n, peerSeen.Load().(string))
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
	}
}

// startTunForwarders exposes the iran user ports, landing on the kharej
// tunnel address (or an explicit host:port).
// Bytes are already counted at the tun device, so the forwarders get no tracker.
func startTunForwarders(ctx context.Context, cfg *config.Config, peerTun string, _ *status.Tracker) error {
	resolve := func(t string) string {
		if _, err := strconv.Atoi(t); err == nil {
			return net.JoinHostPort(peerTun, t)
		}
		return t
	}
	tcp, _ := config.ParsePorts(cfg.TCPPorts)
	udp, _ := config.ParsePorts(cfg.UDPPorts)
	for _, m := range tcp {
		addr := resolve(m.Target)
		if err := fwd.TCP(ctx, cfg.BindIP, m.Listen, func() (net.Conn, error) {
			return net.DialTimeout("tcp", addr, 10*time.Second)
		}, nil); err != nil {
			return err
		}
	}
	for _, m := range udp {
		addr := resolve(m.Target)
		if err := fwd.UDP(ctx, cfg.BindIP, m.Listen, func() (net.Conn, error) {
			return net.Dial("udp", addr)
		}, nil); err != nil {
			return err
		}
	}
	return nil
}

// lossMeter turns the gaps in the peer's keepalive numbers into a loss
// percentage. A link can stay "connected" on the odd keepalive that gets
// through while dropping nearly all traffic; this is what shows it.
type lossMeter struct {
	mu          sync.Mutex
	first, last uint32
	got         int
}

const lossWindow = 8 // keepalives per measurement (~24s)

func (m *lossMeter) reset() {
	m.mu.Lock()
	m.got = 0
	m.mu.Unlock()
}

func (m *lossMeter) seen(seq uint32, st *status.Tracker) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.got == 0 || seq <= m.last { // first one, or the peer restarted
		m.first, m.last, m.got = seq, seq, 1
		return
	}
	m.last = seq
	m.got++
	if span := int(m.last-m.first) + 1; span >= lossWindow {
		pct := 100 * (span - m.got) / span
		if pct < 0 {
			pct = 0
		}
		st.SetLoss(pct)
		m.first, m.got = seq, 1
	}
}
