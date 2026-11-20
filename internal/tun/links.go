package tun

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

	"github.com/darktunnelmika/max-dark-tunnel/internal/crypt"
)

// Link moves already-sealed packets between the two servers.
type Link interface {
	Send(p []byte) error
	Recv(b []byte) (int, net.Addr, error)
	// Confirm is called after a packet from addr authenticated, so a
	// listening side learns where to reply.
	Confirm(addr net.Addr)
	Close()
}

var errNoPeer = errors.New("peer not known yet")

// ------------------------------------------------------------- raw IP -------

type rawLink struct {
	pc   net.PacketConn
	peer *net.IPAddr
}

func newRaw(bind string, proto int, peer string) (*rawLink, error) {
	pc, err := net.ListenPacket("ip4:"+strconv.Itoa(proto), bind)
	if err != nil {
		return nil, err
	}
	return &rawLink{pc: pc, peer: &net.IPAddr{IP: net.ParseIP(peer)}}, nil
}

func (l *rawLink) Send(p []byte) error { _, err := l.pc.WriteTo(p, l.peer); return err }
func (l *rawLink) Recv(b []byte) (int, net.Addr, error) {
	for {
		n, from, err := l.pc.ReadFrom(b)
		if err != nil {
			return 0, nil, err
		}
		if a, ok := from.(*net.IPAddr); ok && a.IP.Equal(l.peer.IP) {
			return n, from, nil
		}
	}
}
func (l *rawLink) Confirm(net.Addr) {}
func (l *rawLink) Close()           { l.pc.Close() }

// --------------------------------------------------------------- ICMP -------

type icmpLink struct {
	pc        net.PacketConn
	peer      *net.IPAddr
	sendType  byte
	recvType  byte
	code      byte
	id        uint16
	seq       atomic.Uint32
	mirrorSeq bool // kharej answers with the last seq it saw, like a real ping reply
	sendBuf   []byte
	mu        sync.Mutex
}

func newICMP(bind, peer string, sendType, recvType, code int, id uint16, mirror bool) (*icmpLink, error) {
	pc, err := net.ListenPacket("ip4:icmp", bind)
	if err != nil {
		return nil, err
	}
	return &icmpLink{pc: pc, peer: &net.IPAddr{IP: net.ParseIP(peer)},
		sendType: byte(sendType), recvType: byte(recvType), code: byte(code), id: id, mirrorSeq: mirror}, nil
}

func csum(b []byte) uint16 {
	var s uint32
	for i := 0; i+1 < len(b); i += 2 {
		s += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)%2 == 1 {
		s += uint32(b[len(b)-1]) << 8
	}
	for s>>16 != 0 {
		s = s&0xffff + s>>16
	}
	return ^uint16(s)
}

func (l *icmpLink) Send(p []byte) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	b := append(l.sendBuf[:0], l.sendType, l.code, 0, 0, 0, 0, 0, 0)
	binary.BigEndian.PutUint16(b[4:], l.id)
	var seq uint16
	if l.mirrorSeq {
		seq = uint16(l.seq.Load())
	} else {
		seq = uint16(l.seq.Add(1))
	}
	binary.BigEndian.PutUint16(b[6:], seq)
	b = append(b, p...)
	binary.BigEndian.PutUint16(b[2:], csum(b))
	l.sendBuf = b
	_, err := l.pc.WriteTo(b, l.peer)
	return err
}

func (l *icmpLink) Recv(b []byte) (int, net.Addr, error) {
	for {
		n, from, err := l.pc.ReadFrom(b)
		if err != nil {
			return 0, nil, err
		}
		a, ok := from.(*net.IPAddr)
		if !ok || !a.IP.Equal(l.peer.IP) || n < 8+crypt.PacketOverhead {
			continue
		}
		if b[0] != l.recvType || b[1] != l.code || binary.BigEndian.Uint16(b[4:]) != l.id {
			continue
		}
		if l.mirrorSeq {
			l.seq.Store(uint32(binary.BigEndian.Uint16(b[6:])))
		}
		copy(b, b[8:n])
		return n - 8, from, nil
	}
}
func (l *icmpLink) Confirm(net.Addr) {}
func (l *icmpLink) Close()           { l.pc.Close() }

// ---------------------------------------------------------------- UDP -------

// udpLink: the listening side learns the peer from the last packet that
// authenticated; the dialing side has a fixed peer.
type udpLink struct {
	pc     net.PacketConn
	peer   atomic.Pointer[net.UDPAddr]
	listen bool
	// wrap/unwrap let the DNS link reuse everything else.
	wrap   func(dst, p []byte) []byte
	unwrap func(b []byte) ([]byte, bool)
	mu     sync.Mutex
	wbuf   []byte
}

func newUDP(bind string, port int, peer string, listen bool) (*udpLink, error) {
	l := &udpLink{listen: listen}
	var err error
	if listen {
		l.pc, err = net.ListenPacket("udp4", net.JoinHostPort(bind, strconv.Itoa(port)))
	} else {
		l.pc, err = net.ListenPacket("udp4", ":0")
		if err == nil {
			l.peer.Store(&net.UDPAddr{IP: net.ParseIP(peer), Port: port})
		}
	}
	return l, err
}

func (l *udpLink) Send(p []byte) error {
	to := l.peer.Load()
	if to == nil {
		return errNoPeer
	}
	if l.wrap != nil {
		l.mu.Lock()
		defer l.mu.Unlock()
		l.wbuf = l.wrap(l.wbuf[:0], p)
		p = l.wbuf
	}
	_, err := l.pc.WriteTo(p, to)
	return err
}

func (l *udpLink) Recv(b []byte) (int, net.Addr, error) {
	for {
		n, from, err := l.pc.ReadFrom(b)
		if err != nil {
			return 0, nil, err
		}
		if !l.listen {
			if p := l.peer.Load(); p == nil || !from.(*net.UDPAddr).IP.Equal(p.IP) {
				continue
			}
		}
		if l.unwrap != nil {
			pl, ok := l.unwrap(b[:n])
			if !ok {
				continue
			}
			n = copy(b, pl)
		}
		return n, from, nil
	}
}

func (l *udpLink) Confirm(a net.Addr) {
	if !l.listen {
		return
	}
	if u, ok := a.(*net.UDPAddr); ok {
		if cur := l.peer.Load(); cur == nil || cur.String() != u.String() {
			l.peer.Store(u)
		}
	}
}
func (l *udpLink) Close() { l.pc.Close() }

// ---------------------------------------------------------------- TCP -------

// tcpLink carries packets length-framed over one encrypted TCP connection,
// redialing (or re-accepting) whenever it drops.
type tcpLink struct {
	mu   sync.Mutex
	cur  net.Conn
	in   chan []byte
	stop context.CancelFunc
}

func newTCP(ctx context.Context, bind string, port int, peer, psk string, listen bool) (*tcpLink, error) {
	ctx, cancel := context.WithCancel(ctx)
	l := &tcpLink{in: make(chan []byte, 1024), stop: cancel}
	if listen {
		ln, err := net.Listen("tcp4", net.JoinHostPort(bind, strconv.Itoa(port)))
		if err != nil {
			cancel()
			return nil, err
		}
		go func() { <-ctx.Done(); ln.Close() }()
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					if ctx.Err() != nil {
						return
					}
					continue
				}
				go func() {
					sc, err := crypt.Server(c, psk)
					if err != nil {
						log.Printf("rejected %s: %v", c.RemoteAddr(), err)
						c.Close()
						return
					}
					l.attach(sc)
				}()
			}
		}()
	} else {
		addr := net.JoinHostPort(peer, strconv.Itoa(port))
		go func() {
			backoff := time.Second
			for ctx.Err() == nil {
				c, err := net.DialTimeout("tcp4", addr, 10*time.Second)
				if err == nil {
					var sc *crypt.Conn
					if sc, err = crypt.Client(c, psk); err == nil {
						backoff = time.Second
						l.attach(sc) // blocks until it drops
						continue
					}
					c.Close()
				}
				log.Printf("carrier %s: %v (retry in %s)", addr, err, backoff)
				time.Sleep(backoff)
				if backoff < 15*time.Second {
					backoff *= 2
				}
			}
		}()
	}
	return l, nil
}

func (l *tcpLink) attach(c net.Conn) {
	if t, ok := c.(interface{ SetNoDelay(bool) error }); ok {
		_ = t.SetNoDelay(true)
	}
	l.mu.Lock()
	if l.cur != nil {
		l.cur.Close()
	}
	l.cur = c
	l.mu.Unlock()
	var h [2]byte
	for {
		_ = c.SetReadDeadline(time.Now().Add(40 * time.Second))
		if _, err := io.ReadFull(c, h[:]); err != nil {
			break
		}
		p := make([]byte, binary.BigEndian.Uint16(h[:]))
		if _, err := io.ReadFull(c, p); err != nil {
			break
		}
		select {
		case l.in <- p:
		default: // drop on overload, like a real link
		}
	}
	c.Close()
	l.mu.Lock()
	if l.cur == c {
		l.cur = nil
	}
	l.mu.Unlock()
}

func (l *tcpLink) Send(p []byte) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.cur == nil {
		return errNoPeer
	}
	b := make([]byte, 2+len(p))
	binary.BigEndian.PutUint16(b, uint16(len(p)))
	copy(b[2:], p)
	_ = l.cur.SetWriteDeadline(time.Now().Add(10 * time.Second))
	_, err := l.cur.Write(b)
	return err
}

func (l *tcpLink) Recv(b []byte) (int, net.Addr, error) {
	p, ok := <-l.in
	if !ok {
		return 0, nil, io.EOF
	}
	return copy(b, p), nil, nil
}
func (l *tcpLink) Confirm(net.Addr) {}
func (l *tcpLink) Close()           { l.stop() }
