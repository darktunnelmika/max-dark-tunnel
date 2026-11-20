// Package stream implements the TCP Forward and SSH transports: a pool of
// carrier sessions between the two servers, each carrying many streams.
// Iran always opens the streams (users arrive there); kharej dials the real
// service for each one. Which side dials the carrier is set by direction.
package stream

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"log"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/darktunnelmika/max-dark-tunnel/internal/config"
	"github.com/darktunnelmika/max-dark-tunnel/internal/fwd"
	"github.com/darktunnelmika/max-dark-tunnel/internal/status"
)

// Session is one carrier connection carrying many streams.
type Session interface {
	Open() (net.Conn, error)
	Accept() (net.Conn, error)
	Close() error
	IsClosed() bool
}

// Builder turns a raw carrier connection into a session.
type Builder func(c net.Conn, dialer bool) (Session, error)

type pool struct {
	mu   sync.Mutex
	list []Session
	rr   atomic.Uint32
}

func (p *pool) add(s Session) {
	p.mu.Lock()
	p.list = append(p.list, s)
	p.mu.Unlock()
}

func (p *pool) live() []Session {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := p.list[:0]
	for _, s := range p.list {
		if !s.IsClosed() {
			out = append(out, s)
		}
	}
	p.list = out
	return append([]Session(nil), out...)
}

func (p *pool) open() (net.Conn, error) {
	l := p.live()
	if len(l) == 0 {
		return nil, errors.New("no carrier session")
	}
	start := int(p.rr.Add(1))
	for i := range l {
		s := l[(start+i)%len(l)]
		if c, err := s.Open(); err == nil {
			return c, nil
		}
		s.Close()
	}
	return nil, errors.New("all carrier sessions failed")
}

// Run blocks forever, keeping the carrier up and serving streams.
func Run(ctx context.Context, cfg *config.Config, build Builder, st *status.Tracker) error {
	p := &pool{}
	peer := cfg.PeerIP()

	go func() {
		for {
			n := len(p.live())
			st.Set(n > 0, n, peer)
			select {
			case <-ctx.Done():
				return
			case <-time.After(2 * time.Second):
			}
		}
	}()

	serve := func(s Session) {
		p.add(s)
		if cfg.IsIran() {
			for !s.IsClosed() {
				time.Sleep(time.Second)
			}
			return
		}
		for {
			c, err := s.Accept()
			if err != nil {
				s.Close()
				return
			}
			go handleStream(c, st)
		}
	}

	if cfg.IsIran() {
		if err := startForwarders(ctx, cfg, p, st); err != nil {
			return err
		}
	}

	if cfg.Listens() {
		addr := net.JoinHostPort(cfg.BindIP, strconv.Itoa(cfg.Port))
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			return err
		}
		log.Printf("carrier listening on %s (%s)", addr, cfg.Transport)
		go func() { <-ctx.Done(); ln.Close() }()
		for {
			c, err := ln.Accept()
			if err != nil {
				if ctx.Err() != nil {
					return nil
				}
				time.Sleep(100 * time.Millisecond)
				continue
			}
			tune(c)
			go func() {
				s, err := build(c, false)
				if err != nil {
					log.Printf("rejected %s: %v", c.RemoteAddr(), err)
					c.Close()
					return
				}
				log.Printf("session from %s", c.RemoteAddr())
				serve(s)
			}()
		}
	}

	addr := net.JoinHostPort(peer, strconv.Itoa(cfg.Port))
	log.Printf("carrier dialing %s (%s, %d sessions)", addr, cfg.Transport, cfg.Mux)
	for i := 0; i < cfg.Mux; i++ {
		go func(i int) {
			backoff := time.Second
			for ctx.Err() == nil {
				c, err := net.DialTimeout("tcp", addr, 10*time.Second)
				if err == nil {
					tune(c)
					var s Session
					s, err = build(c, true)
					if err == nil {
						backoff = time.Second
						serve(s)
						log.Printf("session %d closed", i)
						continue
					}
					c.Close()
				}
				log.Printf("session %d: %v (retry in %s)", i, err, backoff)
				time.Sleep(backoff)
				if backoff < 15*time.Second {
					backoff *= 2
				}
			}
		}(i)
	}
	<-ctx.Done()
	return nil
}

func tune(c net.Conn) {
	if t, ok := c.(*net.TCPConn); ok {
		_ = t.SetNoDelay(true)
		_ = t.SetKeepAlive(true)
		_ = t.SetKeepAlivePeriod(20 * time.Second)
	}
}

// ------------------------------------------------------------ stream header -

const (
	kindTCP = 'T'
	kindUDP = 'U'
)

func writeHeader(c net.Conn, kind byte, target string) error {
	b := append([]byte{kind, byte(len(target))}, target...)
	_, err := c.Write(b)
	return err
}

func readHeader(c net.Conn) (byte, string, error) {
	var h [2]byte
	if _, err := io.ReadFull(c, h[:]); err != nil {
		return 0, "", err
	}
	t := make([]byte, h[1])
	if _, err := io.ReadFull(c, t); err != nil {
		return 0, "", err
	}
	return h[0], string(t), nil
}

// targetAddr: a bare port means the kharej loopback.
func targetAddr(t string) string {
	if _, err := strconv.Atoi(t); err == nil {
		return net.JoinHostPort("127.0.0.1", t)
	}
	return t
}

// handleStream runs on kharej for every stream iran opens.
func handleStream(c net.Conn, st *status.Tracker) {
	defer c.Close()
	_ = c.SetReadDeadline(time.Now().Add(15 * time.Second))
	kind, target, err := readHeader(c)
	_ = c.SetReadDeadline(time.Time{})
	if err != nil {
		return
	}
	switch kind {
	case kindTCP:
		r, err := net.DialTimeout("tcp", targetAddr(target), 10*time.Second)
		if err != nil {
			log.Printf("dial %s: %v", target, err)
			return
		}
		tune(r)
		fwd.Pipe(c, r, st)
	case kindUDP:
		r, err := net.Dial("udp", targetAddr(target))
		if err != nil {
			return
		}
		relayUDP(&Framed{Conn: c}, r, st)
	}
}

// Framed carries datagrams over a stream with a 2-byte length prefix.
type Framed struct {
	net.Conn
	wmu sync.Mutex
}

func (f *Framed) Write(p []byte) (int, error) {
	f.wmu.Lock()
	defer f.wmu.Unlock()
	b := make([]byte, 2+len(p))
	binary.BigEndian.PutUint16(b, uint16(len(p)))
	copy(b[2:], p)
	if _, err := f.Conn.Write(b); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (f *Framed) Read(p []byte) (int, error) {
	var h [2]byte
	if _, err := io.ReadFull(f.Conn, h[:]); err != nil {
		return 0, err
	}
	n := int(binary.BigEndian.Uint16(h[:]))
	if n > len(p) {
		buf := make([]byte, n)
		if _, err := io.ReadFull(f.Conn, buf); err != nil {
			return 0, err
		}
		return copy(p, buf), nil
	}
	return io.ReadFull(f.Conn, p[:n])
}

// relayUDP shuttles datagrams between two datagram-preserving conns until idle.
func relayUDP(a, b net.Conn, st *status.Tracker) {
	const idle = 90 * time.Second
	done := make(chan struct{}, 2)
	cp := func(dst, src net.Conn, rx bool) {
		buf := make([]byte, 65535)
		for {
			_ = src.SetReadDeadline(time.Now().Add(idle))
			n, err := src.Read(buf)
			if err != nil {
				break
			}
			if _, err := dst.Write(buf[:n]); err != nil {
				break
			}
			if rx {
				st.AddRx(n)
			} else {
				st.AddTx(n)
			}
		}
		done <- struct{}{}
	}
	go cp(a, b, true)
	go cp(b, a, false)
	<-done
	a.Close()
	b.Close()
}

// startForwarders exposes the iran user ports, each opening a stream.
func startForwarders(ctx context.Context, cfg *config.Config, p *pool, st *status.Tracker) error {
	tcp, _ := config.ParsePorts(cfg.TCPPorts)
	udp, _ := config.ParsePorts(cfg.UDPPorts)
	for _, m := range tcp {
		target := m.Target
		dial := func() (net.Conn, error) {
			c, err := p.open()
			if err != nil {
				return nil, err
			}
			if err := writeHeader(c, kindTCP, target); err != nil {
				c.Close()
				return nil, err
			}
			return c, nil
		}
		if err := fwd.TCP(ctx, cfg.BindIP, m.Listen, dial, st); err != nil {
			return err
		}
	}
	for _, m := range udp {
		target := m.Target
		dial := func() (net.Conn, error) {
			c, err := p.open()
			if err != nil {
				return nil, err
			}
			if err := writeHeader(c, kindUDP, target); err != nil {
				c.Close()
				return nil, err
			}
			return &Framed{Conn: c}, nil
		}
		if err := fwd.UDP(ctx, cfg.BindIP, m.Listen, dial, st); err != nil {
			return err
		}
	}
	return nil
}
