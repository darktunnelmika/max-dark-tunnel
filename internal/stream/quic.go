package stream

import (
	"bytes"
	"context"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"log"
	"math/big"
	"net"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
	"golang.org/x/crypto/chacha20"

	"github.com/darktunnelmika/max-dark-tunnel/internal/config"
	"github.com/darktunnelmika/max-dark-tunnel/internal/crypt"
)

// QUIC returns a Carrier that tunnels over a single QUIC connection. QUIC
// multiplexes streams natively without the head-of-line blocking of a
// TCP+mux carrier, carries its own TLS 1.3, and recovers from loss well -
// a level above tcpmux, where the path allows UDP.
func QUIC() Carrier { return quicCarrier{} }

type quicCarrier struct{}

func obfsTag(cfg *config.Config) string {
	if cfg.PlainQUIC {
		return ""
	}
	return ", obfuscated"
}

// listenPacket opens the UDP socket quic-go runs on. Unless disabled, it wraps
// it in a packet obfuscator so the QUIC header is scrambled and the flow looks
// like random UDP - some DPI (Iran's, measured) drops recognisable QUIC
// packets while passing opaque UDP.
func listenPacket(addr string, cfg *config.Config) (net.PacketConn, error) {
	ua, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	uc, err := net.ListenUDP("udp", ua)
	if err != nil {
		return nil, err
	}
	if cfg.PlainQUIC {
		return uc, nil
	}
	return newObfsConn(uc, crypt.Derive(cfg.PSK, nil, "quic obfs key", 32)), nil
}

func (quicCarrier) Listen(ctx context.Context, cfg *config.Config, serve func(Session)) error {
	addr := net.JoinHostPort(cfg.BindIP, strconv.Itoa(cfg.Port))
	pc, err := listenPacket(addr, cfg)
	if err != nil {
		return err
	}
	ln, err := quic.Listen(pc, serverTLS(cfg.PSK), quicConf(cfg))
	if err != nil {
		pc.Close()
		return err
	}
	log.Printf("carrier listening on %s (quic%s)", addr, obfsTag(cfg))
	go func() { <-ctx.Done(); ln.Close() }()
	for {
		conn, err := ln.Accept(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			time.Sleep(200 * time.Millisecond)
			continue
		}
		log.Printf("session from %s", conn.RemoteAddr())
		go serve(&quicSess{conn: conn})
	}
}

func (quicCarrier) Dial(ctx context.Context, cfg *config.Config, serve func(Session)) error {
	raddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(cfg.PeerIP(), strconv.Itoa(cfg.Port)))
	if err != nil {
		return err
	}
	log.Printf("carrier dialing %s (quic%s)", raddr, obfsTag(cfg))
	backoff := time.Second
	for ctx.Err() == nil {
		pc, perr := listenPacket(":0", cfg)
		if perr != nil {
			return perr
		}
		dctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		conn, err := quic.Dial(dctx, pc, raddr, clientTLS(cfg.PSK), quicConf(cfg))
		cancel()
		if err == nil {
			backoff = time.Second
			serve(&quicSess{conn: conn})
			log.Printf("quic session closed")
			pc.Close()
			continue
		}
		pc.Close()
		log.Printf("quic dial %s: %v (retry in %s)", raddr, err, backoff)
		time.Sleep(backoff)
		if backoff < 15*time.Second {
			backoff *= 2
		}
	}
	return nil
}

func quicConf(cfg *config.Config) *quic.Config {
	ka := cfg.KeepAliveDur()
	if ka <= 0 {
		ka = 10 * time.Second
	}
	return &quic.Config{
		MaxIdleTimeout:        3 * ka,
		KeepAlivePeriod:       ka,
		HandshakeIdleTimeout:  10 * time.Second,
		MaxIncomingStreams:    1 << 16,
		MaxIncomingUniStreams: -1,
		EnableDatagrams:       false,
	}
}

// ------------------------------------------------------------- session ------

type quicSess struct {
	conn   quic.Connection
	closed atomic.Bool
}

func (q *quicSess) wrap(s quic.Stream) net.Conn {
	return &quicStream{Stream: s, local: q.conn.LocalAddr(), remote: q.conn.RemoteAddr()}
}

func (q *quicSess) Open() (net.Conn, error) {
	s, err := q.conn.OpenStreamSync(context.Background())
	if err != nil {
		return nil, err
	}
	return q.wrap(s), nil
}

func (q *quicSess) Accept() (net.Conn, error) {
	s, err := q.conn.AcceptStream(context.Background())
	if err != nil {
		return nil, err
	}
	return q.wrap(s), nil
}

func (q *quicSess) Close() error {
	q.closed.Store(true)
	return q.conn.CloseWithError(0, "")
}

func (q *quicSess) IsClosed() bool {
	if q.closed.Load() {
		return true
	}
	select {
	case <-q.conn.Context().Done():
		return true
	default:
		return false
	}
}

// quicStream adapts a QUIC stream to net.Conn (it has no addresses of its own).
type quicStream struct {
	quic.Stream
	local, remote net.Addr
	done          atomic.Bool
}

func (s *quicStream) LocalAddr() net.Addr  { return s.local }
func (s *quicStream) RemoteAddr() net.Addr { return s.remote }

// CloseWrite half-closes the send direction, which is what fwd.Pipe wants.
func (s *quicStream) CloseWrite() error { return s.Stream.Close() }

func (s *quicStream) Close() error {
	if s.done.Swap(true) {
		return nil
	}
	s.Stream.CancelRead(0)
	_ = s.Stream.Close()
	return nil
}

// ---------------------------------------------------------------- TLS -------

// pskCert builds a self-signed certificate whose Ed25519 key is derived
// deterministically from the PSK, so both sides compute the identical keypair
// and certificate and can pin each other's public key. Ed25519 (unlike ECDSA)
// is deterministic from a seed and signs deterministically, so the DER is
// reproducible. Returns the certificate and the marshalled public key to pin.
func pskCert(psk string) (tls.Certificate, []byte) {
	priv := ed25519.NewKeyFromSeed(crypt.Derive(psk, nil, "quic ed25519 seed", ed25519.SeedSize))
	pubKey := priv.Public().(ed25519.PublicKey)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "www.bing.com"},
		NotBefore:    time.Unix(1700000000, 0),
		NotAfter:     time.Unix(1700000000+10*365*24*3600, 0),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pubKey, priv)
	if err != nil {
		panic(err)
	}
	pub, _ := x509.MarshalPKIXPublicKey(pubKey)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}, pub
}

// verifyPinned accepts a peer only if it presents the PSK-derived public key.
func verifyPinned(expectedPub []byte) func([][]byte, [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return errors.New("no peer certificate")
		}
		cert, err := x509.ParseCertificate(rawCerts[0])
		if err != nil {
			return err
		}
		pub, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
		if err != nil {
			return err
		}
		if !bytes.Equal(pub, expectedPub) {
			return errors.New("peer key mismatch (wrong psk?)")
		}
		return nil
	}
}

func pskALPN(psk string) string {
	return "mdt" + hex.EncodeToString(crypt.Derive(psk, nil, "quic alpn", 3))
}

func serverTLS(psk string) *tls.Config {
	cert, pub := pskCert(psk)
	return &tls.Config{
		Certificates:          []tls.Certificate{cert},
		ClientAuth:            tls.RequireAnyClientCert,
		VerifyPeerCertificate: verifyPinned(pub),
		NextProtos:            []string{pskALPN(psk)},
		MinVersion:            tls.VersionTLS13,
	}
}

func clientTLS(psk string) *tls.Config {
	cert, pub := pskCert(psk)
	return &tls.Config{
		Certificates:          []tls.Certificate{cert},
		InsecureSkipVerify:    true, // we pin the key ourselves
		VerifyPeerCertificate: verifyPinned(pub),
		NextProtos:            []string{pskALPN(psk)},
		ServerName:            "www.bing.com",
		MinVersion:            tls.VersionTLS13,
	}
}

// ------------------------------------------------------- obfuscation --------

// obfsConn scrambles every datagram with a per-packet keystream so the QUIC
// header never appears on the wire. This is camouflage, not security (QUIC's
// own TLS provides that): the goal is only to defeat QUIC fingerprinting.
// Wire format: 8-byte random salt || (payload XOR chacha20(sha256(key||salt))).
type obfsConn struct {
	net.PacketConn
	key []byte
}

const obfsSaltLen = 8

func newObfsConn(pc net.PacketConn, key []byte) *obfsConn {
	return &obfsConn{PacketConn: pc, key: key}
}

func (o *obfsConn) stream(salt []byte) cipher.Stream {
	h := sha256.New()
	h.Write(o.key)
	h.Write(salt)
	sum := h.Sum(nil)
	c, _ := chacha20.NewUnauthenticatedCipher(sum, make([]byte, chacha20.NonceSize))
	return c
}

func (o *obfsConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	buf := make([]byte, obfsSaltLen+len(p))
	if _, err := rand.Read(buf[:obfsSaltLen]); err != nil {
		return 0, err
	}
	o.stream(buf[:obfsSaltLen]).XORKeyStream(buf[obfsSaltLen:], p)
	if _, err := o.PacketConn.WriteTo(buf, addr); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (o *obfsConn) ReadFrom(b []byte) (int, net.Addr, error) {
	buf := make([]byte, len(b)+obfsSaltLen+64)
	for {
		n, addr, err := o.PacketConn.ReadFrom(buf)
		if err != nil {
			return 0, addr, err
		}
		if n < obfsSaltLen {
			continue // too short to be ours
		}
		pt := n - obfsSaltLen
		if pt > len(b) {
			pt = len(b)
		}
		o.stream(buf[:obfsSaltLen]).XORKeyStream(b[:pt], buf[obfsSaltLen:obfsSaltLen+pt])
		return pt, addr, nil
	}
}
