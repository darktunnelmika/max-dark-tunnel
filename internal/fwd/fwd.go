// Package fwd exposes the user-facing ports on the iran server.
package fwd

import (
	"context"
	"io"
	"log"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/darktunnelmika/max-dark-tunnel/internal/status"
)

// Dialer opens the path to kharej for one user connection. For UDP it must
// return a datagram-preserving conn.
type Dialer func() (net.Conn, error)

// TCP listens on bind:port and pipes each connection through dial.
func TCP(ctx context.Context, bind string, port int, dial Dialer, st *status.Tracker) error {
	addr := net.JoinHostPort(bind, strconv.Itoa(port))
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	log.Printf("forward tcp %s", addr)
	go func() { <-ctx.Done(); ln.Close() }()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				time.Sleep(50 * time.Millisecond)
				continue
			}
			go func() {
				if t, ok := c.(*net.TCPConn); ok {
					_ = t.SetNoDelay(true)
				}
				r, err := dial()
				if err != nil {
					c.Close()
					return
				}
				Pipe(c, r, st)
			}()
		}
	}()
	return nil
}

type udpSess struct {
	c    net.Conn
	last time.Time
}

// UDP listens on bind:port and relays each client address through its own dial.
func UDP(ctx context.Context, bind string, port int, dial Dialer, st *status.Tracker) error {
	addr := net.JoinHostPort(bind, strconv.Itoa(port))
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		return err
	}
	log.Printf("forward udp %s", addr)
	var mu sync.Mutex
	sess := map[string]*udpSess{}
	go func() { <-ctx.Done(); pc.Close() }()
	go func() { // idle sweep
		for range time.Tick(30 * time.Second) {
			mu.Lock()
			for k, s := range sess {
				if time.Since(s.last) > 2*time.Minute {
					s.c.Close()
					delete(sess, k)
				}
			}
			mu.Unlock()
		}
	}()
	go func() {
		buf := make([]byte, 65535)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				continue
			}
			key := from.String()
			mu.Lock()
			s := sess[key]
			mu.Unlock()
			if s == nil {
				c, err := dial()
				if err != nil {
					continue
				}
				s = &udpSess{c: c}
				mu.Lock()
				sess[key] = s
				mu.Unlock()
				go func(from net.Addr, s *udpSess) {
					rb := make([]byte, 65535)
					for {
						m, err := s.c.Read(rb)
						if err != nil {
							break
						}
						_, _ = pc.WriteTo(rb[:m], from)
						st.AddRx(m)
					}
					mu.Lock()
					if sess[from.String()] == s {
						delete(sess, from.String())
					}
					mu.Unlock()
					s.c.Close()
				}(from, s)
			}
			s.last = time.Now()
			if _, err := s.c.Write(buf[:n]); err == nil {
				st.AddTx(n)
			}
		}
	}()
	return nil
}

// Pipe copies both ways with proper half-close, then closes both.
func Pipe(a, b net.Conn, st *status.Tracker) {
	var wg sync.WaitGroup
	wg.Add(2)
	cp := func(dst, src net.Conn, rx bool) {
		defer wg.Done()
		buf := make([]byte, 32*1024)
		n, _ := io.CopyBuffer(dst, src, buf)
		if st != nil {
			if rx {
				st.AddRx(int(n))
			} else {
				st.AddTx(int(n))
			}
		}
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		} else {
			_ = dst.Close()
		}
	}
	go cp(a, b, true)
	go cp(b, a, false)
	wg.Wait()
	a.Close()
	b.Close()
}
