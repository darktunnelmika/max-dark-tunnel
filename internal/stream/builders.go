package stream

import (
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"net"
	"sync/atomic"
	"time"

	"github.com/xtaci/smux"
	"golang.org/x/crypto/ssh"

	"github.com/darktunnelmika/max-dark-tunnel/internal/crypt"
)

// ------------------------------------------------------------------ smux ---

type smuxSess struct{ s *smux.Session }

func (m smuxSess) Open() (net.Conn, error)   { return m.s.OpenStream() }
func (m smuxSess) Accept() (net.Conn, error) { return m.s.AcceptStream() }
func (m smuxSess) Close() error              { return m.s.Close() }
func (m smuxSess) IsClosed() bool            { return m.s.IsClosed() }

// Smux: encrypted carrier + stream multiplexing. Iran is the smux client
// (it opens streams) whichever side dialed.
func Smux(psk string, iran bool) Builder {
	return func(c net.Conn, dialer bool) (Session, error) {
		var sc *crypt.Conn
		var err error
		if dialer {
			sc, err = crypt.Client(c, psk)
		} else {
			sc, err = crypt.Server(c, psk)
		}
		if err != nil {
			return nil, err
		}
		cfg := smux.DefaultConfig()
		cfg.Version = 2
		cfg.KeepAliveInterval = 10 * time.Second
		cfg.KeepAliveTimeout = 30 * time.Second
		cfg.MaxReceiveBuffer = 8 << 20
		cfg.MaxStreamBuffer = 2 << 20
		cfg.MaxFrameSize = 16 * 1024
		var s *smux.Session
		if iran {
			s, err = smux.Client(sc, cfg)
		} else {
			s, err = smux.Server(sc, cfg)
		}
		if err != nil {
			return nil, err
		}
		return smuxSess{s}, nil
	}
}

// ------------------------------------------------------------------- ssh ---

const chanType = "mdt"

type sshSess struct {
	conn   ssh.Conn
	chans  <-chan ssh.NewChannel
	closed atomic.Bool
}

func newSSHSess(conn ssh.Conn, chans <-chan ssh.NewChannel, reqs <-chan *ssh.Request) *sshSess {
	s := &sshSess{conn: conn, chans: chans}
	go func() {
		for r := range reqs {
			if r.WantReply {
				_ = r.Reply(true, nil) // keepalives
			}
		}
	}()
	go func() { _ = conn.Wait(); s.closed.Store(true) }()
	go func() { // keepalive; drops a dead session within ~30s
		for !s.closed.Load() {
			time.Sleep(10 * time.Second)
			done := make(chan error, 1)
			go func() { _, _, err := conn.SendRequest("keepalive@openssh.com", true, nil); done <- err }()
			select {
			case err := <-done:
				if err != nil {
					s.Close()
				}
			case <-time.After(20 * time.Second):
				s.Close()
			}
		}
	}()
	return s
}

func (s *sshSess) Open() (net.Conn, error) {
	ch, reqs, err := s.conn.OpenChannel(chanType, nil)
	if err != nil {
		return nil, err
	}
	go ssh.DiscardRequests(reqs)
	return &chanConn{Channel: ch, l: s.conn.LocalAddr(), r: s.conn.RemoteAddr()}, nil
}

func (s *sshSess) Accept() (net.Conn, error) {
	for nc := range s.chans {
		if nc.ChannelType() != chanType {
			_ = nc.Reject(ssh.UnknownChannelType, "unsupported")
			continue
		}
		ch, reqs, err := nc.Accept()
		if err != nil {
			continue
		}
		go ssh.DiscardRequests(reqs)
		return &chanConn{Channel: ch, l: s.conn.LocalAddr(), r: s.conn.RemoteAddr()}, nil
	}
	return nil, errors.New("ssh session closed")
}

func (s *sshSess) Close() error   { s.closed.Store(true); return s.conn.Close() }
func (s *sshSess) IsClosed() bool { return s.closed.Load() }

type chanConn struct {
	ssh.Channel
	l, r net.Addr
}

func (c *chanConn) LocalAddr() net.Addr                { return c.l }
func (c *chanConn) RemoteAddr() net.Addr               { return c.r }
func (c *chanConn) SetDeadline(t time.Time) error      { return nil }
func (c *chanConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *chanConn) SetWriteDeadline(t time.Time) error { return nil }

// SSH: an embedded SSH server/client pair. The host key and password are
// derived from the PSK, so the client pins the server and nothing else logs in.
func SSH(psk string) Builder {
	signer, _ := ssh.NewSignerFromKey(ed25519.NewKeyFromSeed(crypt.Derive(psk, nil, "ssh hostkey", 32)))
	pass := hex.EncodeToString(crypt.Derive(psk, nil, "ssh password", 24))
	const user = "root"
	return func(c net.Conn, dialer bool) (Session, error) {
		_ = c.SetDeadline(time.Now().Add(15 * time.Second))
		defer c.SetDeadline(time.Time{})
		if dialer {
			cc := &ssh.ClientConfig{
				User:            user,
				Auth:            []ssh.AuthMethod{ssh.Password(pass)},
				HostKeyCallback: ssh.FixedHostKey(signer.PublicKey()),
				ClientVersion:   "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5",
				Timeout:         15 * time.Second,
			}
			conn, chans, reqs, err := ssh.NewClientConn(c, c.RemoteAddr().String(), cc)
			if err != nil {
				return nil, err
			}
			return newSSHSess(conn, chans, reqs), nil
		}
		sc := &ssh.ServerConfig{
			ServerVersion: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10",
			PasswordCallback: func(m ssh.ConnMetadata, p []byte) (*ssh.Permissions, error) {
				if m.User() == user && subtle.ConstantTimeCompare(p, []byte(pass)) == 1 {
					return nil, nil
				}
				time.Sleep(2 * time.Second)
				return nil, errors.New("denied")
			},
			MaxAuthTries: 3,
		}
		sc.AddHostKey(signer)
		conn, chans, reqs, err := ssh.NewServerConn(c, sc)
		if err != nil {
			return nil, err
		}
		return newSSHSess(conn, chans, reqs), nil
	}
}
