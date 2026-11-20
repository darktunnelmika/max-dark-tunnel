package tun

import (
	"crypto/rand"
	"encoding/binary"
	"strings"
)

// DNS framing: iran sends TXT queries for <random>.<domain> carrying the
// packet in an additional TXT record; kharej answers with TXT responses
// carrying its packets. Both ends are ours, so the parser only has to
// understand what the writer produces - but every read is bounds-checked.

const b32 = "abcdefghijklmnopqrstuvwxyz234567"

// sessionLabel is chosen once per process. A fresh random label on every
// query is the textbook DNS-tunnel signature and gets the flow throttled;
// one stable name looks like a client repeatedly asking for the same record.
var sessionLabel = func() []byte {
	var r [8]byte
	_, _ = rand.Read(r[:])
	out := make([]byte, len(r))
	for i, x := range r {
		out[i] = b32[x&31]
	}
	return out
}()

func dnsName(dst []byte, domain string) []byte {
	dst = append(dst, byte(len(sessionLabel)))
	dst = append(dst, sessionLabel...)
	for _, lab := range strings.Split(strings.Trim(domain, "."), ".") {
		if lab == "" || len(lab) > 63 {
			continue
		}
		dst = append(dst, byte(len(lab)))
		dst = append(dst, lab...)
	}
	return append(dst, 0)
}

func txtRData(dst, p []byte) []byte {
	start := len(dst)
	dst = append(dst, 0, 0) // rdlength placeholder
	for len(p) > 0 {
		n := len(p)
		if n > 255 {
			n = 255
		}
		dst = append(dst, byte(n))
		dst = append(dst, p[:n]...)
		p = p[n:]
	}
	if len(p) == 0 && len(dst) == start+2 {
		dst = append(dst, 0) // empty TXT string
	}
	binary.BigEndian.PutUint16(dst[start:], uint16(len(dst)-start-2))
	return dst
}

func dnsWrapper(domain string, query bool) func(dst, p []byte) []byte {
	return func(dst, p []byte) []byte {
		var id [2]byte
		_, _ = rand.Read(id[:])
		dst = append(dst, id[0], id[1])
		if query {
			dst = append(dst, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 1) // RD; qd=1 ar=1
		} else {
			dst = append(dst, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0) // QR RD RA; qd=1 an=1
		}
		dst = dnsName(dst, domain)
		dst = append(dst, 0, 16, 0, 1) // TXT IN
		if query {
			dst = append(dst, 0)                       // root name (EDNS-like position)
			dst = append(dst, 0, 16, 0, 1, 0, 0, 0, 0) // TXT IN ttl 0
		} else {
			dst = append(dst, 0xc0, 0x0c)               // pointer to question
			dst = append(dst, 0, 16, 0, 1, 0, 0, 0, 60) // TXT IN ttl 60
		}
		return txtRData(dst, p)
	}
}

func skipName(b []byte, i int) (int, bool) {
	for i < len(b) {
		l := int(b[i])
		switch {
		case l == 0:
			return i + 1, true
		case l&0xc0 == 0xc0:
			return i + 2, i+2 <= len(b)
		default:
			i += 1 + l
		}
	}
	return 0, false
}

func dnsUnwrapper(wantResponse bool) func(b []byte) ([]byte, bool) {
	return func(b []byte) ([]byte, bool) {
		if len(b) < 12 {
			return nil, false
		}
		if (b[2]&0x80 != 0) != wantResponse {
			return nil, false
		}
		qd := int(binary.BigEndian.Uint16(b[4:]))
		rr := int(binary.BigEndian.Uint16(b[6:])) + int(binary.BigEndian.Uint16(b[8:])) + int(binary.BigEndian.Uint16(b[10:]))
		i := 12
		var ok bool
		for ; qd > 0; qd-- {
			if i, ok = skipName(b, i); !ok || i+4 > len(b) {
				return nil, false
			}
			i += 4
		}
		for ; rr > 0; rr-- {
			if i, ok = skipName(b, i); !ok || i+10 > len(b) {
				return nil, false
			}
			typ := binary.BigEndian.Uint16(b[i:])
			rdl := int(binary.BigEndian.Uint16(b[i+8:]))
			i += 10
			if i+rdl > len(b) {
				return nil, false
			}
			if typ != 16 {
				i += rdl
				continue
			}
			var out []byte
			rd := b[i : i+rdl]
			for len(rd) > 0 {
				n := int(rd[0])
				if 1+n > len(rd) {
					return nil, false
				}
				out = append(out, rd[1:1+n]...)
				rd = rd[1+n:]
			}
			return out, true
		}
		return nil, false
	}
}
