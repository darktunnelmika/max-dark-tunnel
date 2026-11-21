package tun

import (
	"encoding/binary"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
)

// spoofRawLink is the MDTprotocol carrier with a forged source IP. It builds
// the whole IPv4 header itself (IP_HDRINCL) so outgoing packets carry a fake
// source, and on receive it accepts only packets whose source is the fake
// address the peer forges. Real routing is unchanged: packets are still sent
// to the peer's real IP, only the sender field is faked - so a route that
// meters by source IP never sees the real one.
//
// Most datacenters drop packets with a source they did not assign, so this
// only works where egress filtering is loose.
type spoofRawLink struct {
	fd      int
	dst     [4]byte // real peer IP (where packets actually go)
	src     [4]byte // forged source we stamp on our packets
	expect  [4]byte // forged source we accept from the peer
	proto   int
	hdr     []byte // GRE (or other) header after the IP header
	mu      sync.Mutex
	ipid    atomic.Uint32
	sendbuf []byte
}

func ip4(s string) ([4]byte, bool) {
	ip := net.ParseIP(s).To4()
	if ip == nil {
		return [4]byte{}, false
	}
	return [4]byte{ip[0], ip[1], ip[2], ip[3]}, true
}

func newSpoofRaw(proto int, realPeer, spoofSrc, spoofDst, psk string) (*spoofRawLink, error) {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, proto)
	if err != nil {
		return nil, err
	}
	if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1); err != nil {
		syscall.Close(fd)
		return nil, err
	}
	l := &spoofRawLink{fd: fd, proto: proto, hdr: rawHeader(proto, psk)}
	var ok bool
	if l.dst, ok = ip4(realPeer); !ok {
		syscall.Close(fd)
		return nil, errNoPeer
	}
	l.src, _ = ip4(spoofSrc)
	l.expect, _ = ip4(spoofDst)
	return l, nil
}

func (l *spoofRawLink) Send(p []byte) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	body := len(l.hdr) + len(p)
	total := 20 + body
	if cap(l.sendbuf) < total {
		l.sendbuf = make([]byte, total)
	}
	b := l.sendbuf[:total]
	b[0] = 0x45 // IPv4, IHL 5
	b[1] = 0
	binary.BigEndian.PutUint16(b[2:], uint16(total))
	binary.BigEndian.PutUint16(b[4:], uint16(l.ipid.Add(1)))
	binary.BigEndian.PutUint16(b[6:], 0) // no fragmentation
	b[8] = 64                            // TTL
	b[9] = byte(l.proto)
	binary.BigEndian.PutUint16(b[10:], 0) // checksum, filled below
	copy(b[12:16], l.src[:])
	copy(b[16:20], l.dst[:])
	binary.BigEndian.PutUint16(b[10:], ipChecksum(b[:20]))
	copy(b[20:], l.hdr)
	copy(b[20+len(l.hdr):], p)
	return syscall.Sendto(l.fd, b, 0, &syscall.SockaddrInet4{Addr: l.dst})
}

func (l *spoofRawLink) Recv(b []byte) (int, net.Addr, error) {
	buf := make([]byte, len(b)+64)
	for {
		n, _, err := syscall.Recvfrom(l.fd, buf, 0)
		if err != nil {
			return 0, nil, err
		}
		if n < 20 {
			continue
		}
		ihl := int(buf[0]&0x0f) * 4
		if ihl < 20 || n < ihl {
			continue
		}
		var src [4]byte
		copy(src[:], buf[12:16])
		if src != l.expect {
			continue // not the peer's forged source
		}
		payload := buf[ihl:n]
		if h := len(l.hdr); h > 0 {
			if len(payload) < h || !bytesEqual(payload[:h], l.hdr) {
				continue
			}
			payload = payload[h:]
		}
		return copy(b, payload), &net.IPAddr{IP: net.IP(src[:])}, nil
	}
}

func (l *spoofRawLink) Confirm(net.Addr) {}
func (l *spoofRawLink) Close()           { syscall.Close(l.fd) }

func ipChecksum(h []byte) uint16 {
	var s uint32
	for i := 0; i+1 < len(h); i += 2 {
		s += uint32(h[i])<<8 | uint32(h[i+1])
	}
	for s>>16 != 0 {
		s = s&0xffff + s>>16
	}
	return ^uint16(s)
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
