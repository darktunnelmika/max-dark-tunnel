// Package crypt provides the PSK-keyed encryption used by every carrier.
//
// Streams (TCP, tun-over-TCP) use a salted handshake so each connection gets
// fresh per-direction keys and a replayed handshake goes nowhere. Packets
// (raw IP, ICMP, UDP, DNS) use XChaCha20-Poly1305 with a random 24-byte nonce
// and a separate key per direction, so a packet reflected back to its sender
// (an ICMP echo reply, for instance) never decrypts there.
package crypt

import (
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

// Derive returns n bytes bound to the PSK, a salt and a purpose label.
func Derive(psk string, salt []byte, info string, n int) []byte {
	out := make([]byte, n)
	r := hkdf.New(sha256.New, []byte(psk), salt, []byte("max-dark-tunnel/"+info))
	_, _ = io.ReadFull(r, out)
	return out
}

// ---------------------------------------------------------------- packets --

// Packet seals and opens datagrams. Send and receive keys differ per side.
type Packet struct {
	send, recv cipher.AEAD
}

// NewPacket: iran seals with "i2k" and opens "k2i"; kharej the reverse.
func NewPacket(psk string, iran bool) *Packet {
	i2k, _ := chacha20poly1305.NewX(Derive(psk, nil, "pkt i2k", 32))
	k2i, _ := chacha20poly1305.NewX(Derive(psk, nil, "pkt k2i", 32))
	if iran {
		return &Packet{send: i2k, recv: k2i}
	}
	return &Packet{send: k2i, recv: i2k}
}

const PacketOverhead = chacha20poly1305.NonceSizeX + chacha20poly1305.Overhead

// Seal appends nonce||ciphertext of p to dst.
func (k *Packet) Seal(dst, p []byte) []byte {
	n := len(dst)
	dst = append(dst, make([]byte, chacha20poly1305.NonceSizeX)...)
	_, _ = rand.Read(dst[n:])
	return k.send.Seal(dst, dst[n:], p, nil)
}

// Open decrypts b in place-ish; returns error for anything not ours.
func (k *Packet) Open(dst, b []byte) ([]byte, error) {
	if len(b) < PacketOverhead {
		return nil, errors.New("short")
	}
	ns := chacha20poly1305.NonceSizeX
	return k.recv.Open(dst, b[:ns], b[ns:], nil)
}

// ---------------------------------------------------------------- streams --

const (
	saltLen  = 32
	maxFrame = 16 * 1024
	authMsg  = "MDT1-hello"
)

// Conn is an encrypted, authenticated net.Conn.
type Conn struct {
	net.Conn
	wmu        sync.Mutex
	send, recv cipher.AEAD
	sn, rn     uint64
	rbuf       []byte // decrypted bytes not yet returned
	hdr        [2]byte
	wbuf, rraw []byte
}

// Client performs the dialer side of the handshake.
func Client(c net.Conn, psk string) (*Conn, error) { return handshake(c, psk, true) }

// Server performs the listener side. A peer without the PSK learns nothing
// beyond 32 random bytes and is dropped.
func Server(c net.Conn, psk string) (*Conn, error) { return handshake(c, psk, false) }

func handshake(c net.Conn, psk string, client bool) (*Conn, error) {
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	defer c.SetDeadline(time.Time{})

	mine := make([]byte, saltLen)
	_, _ = rand.Read(mine)
	theirs := make([]byte, saltLen)
	var cs, ss []byte
	if client {
		if _, err := c.Write(mine); err != nil {
			return nil, err
		}
		if _, err := io.ReadFull(c, theirs); err != nil {
			return nil, err
		}
		cs, ss = mine, theirs
	} else {
		if _, err := io.ReadFull(c, theirs); err != nil {
			return nil, err
		}
		if _, err := c.Write(mine); err != nil {
			return nil, err
		}
		cs, ss = theirs, mine
	}
	salt := append(append([]byte{}, cs...), ss...)
	c2s, _ := chacha20poly1305.New(Derive(psk, salt, "c2s", 32))
	s2c, _ := chacha20poly1305.New(Derive(psk, salt, "s2c", 32))
	sc := &Conn{Conn: c}
	if client {
		sc.send, sc.recv = c2s, s2c
	} else {
		sc.send, sc.recv = s2c, c2s
	}
	// Client proves it holds the PSK; server proves it back.
	if client {
		if _, err := sc.Write([]byte(authMsg)); err != nil {
			return nil, err
		}
		if err := sc.expectAuth(); err != nil {
			return nil, err
		}
	} else {
		if err := sc.expectAuth(); err != nil {
			return nil, err
		}
		if _, err := sc.Write([]byte(authMsg)); err != nil {
			return nil, err
		}
	}
	return sc, nil
}

func (s *Conn) expectAuth() error {
	b := make([]byte, len(authMsg))
	if _, err := io.ReadFull(s, b); err != nil {
		return errors.New("auth failed (wrong psk?)")
	}
	if string(b) != authMsg {
		return errors.New("auth failed")
	}
	return nil
}

func nonce(n uint64) []byte {
	b := make([]byte, chacha20poly1305.NonceSize)
	binary.BigEndian.PutUint64(b[4:], n)
	return b
}

func (s *Conn) Write(p []byte) (int, error) {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	total := 0
	for len(p) > 0 {
		chunk := p
		if len(chunk) > maxFrame {
			chunk = chunk[:maxFrame]
		}
		need := 2 + len(chunk) + chacha20poly1305.Overhead
		if cap(s.wbuf) < need {
			s.wbuf = make([]byte, 0, 2+maxFrame+chacha20poly1305.Overhead)
		}
		buf := s.wbuf[:2]
		buf = s.send.Seal(buf, nonce(s.sn), chunk, nil)
		s.sn++
		binary.BigEndian.PutUint16(buf[:2], uint16(len(buf)-2))
		if _, err := s.Conn.Write(buf); err != nil {
			return total, err
		}
		total += len(chunk)
		p = p[len(chunk):]
	}
	return total, nil
}

func (s *Conn) Read(p []byte) (int, error) {
	if len(s.rbuf) == 0 {
		if _, err := io.ReadFull(s.Conn, s.hdr[:]); err != nil {
			return 0, err
		}
		n := int(binary.BigEndian.Uint16(s.hdr[:]))
		if n < chacha20poly1305.Overhead || n > maxFrame+chacha20poly1305.Overhead {
			return 0, errors.New("bad frame")
		}
		if cap(s.rraw) < n {
			s.rraw = make([]byte, maxFrame+chacha20poly1305.Overhead)
		}
		raw := s.rraw[:n]
		if _, err := io.ReadFull(s.Conn, raw); err != nil {
			return 0, err
		}
		pt, err := s.recv.Open(raw[:0], nonce(s.rn), raw, nil)
		if err != nil {
			return 0, errors.New("frame auth failed")
		}
		s.rn++
		s.rbuf = pt
	}
	n := copy(p, s.rbuf)
	s.rbuf = s.rbuf[n:]
	return n, nil
}
