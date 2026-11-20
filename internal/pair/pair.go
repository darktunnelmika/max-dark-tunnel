// Package pair turns an iran config into a short code that fully configures
// the kharej side: paste it, and there is nothing else to answer.
package pair

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"

	"github.com/darktunnelmika/max-dark-tunnel/internal/config"
)

const prefix = "MDT-"

type code struct {
	V  int    `json:"v"`
	N  string `json:"n"`
	T  string `json:"t"`
	C  string `json:"c,omitempty"`
	D  string `json:"d,omitempty"`
	P  int    `json:"p,omitempty"`
	I  string `json:"i,omitempty"`
	K  string `json:"k,omitempty"`
	S  string `json:"s"`
	Pr int    `json:"pr,omitempty"`
	It int    `json:"it,omitempty"`
	Ic int    `json:"ic,omitempty"`
	Ir int    `json:"ir,omitempty"`
	Sn int    `json:"sn,omitempty"`
	M  int    `json:"m,omitempty"`
	Dd string `json:"dd,omitempty"`
	Mx int    `json:"mx,omitempty"`
}

// Encode is run on iran.
func Encode(c *config.Config) (string, error) {
	if !c.IsIran() {
		return "", errors.New("pair codes are made on the iran side")
	}
	b, _ := json.Marshal(code{V: 1, N: c.Name, T: c.Transport, C: c.Carrier, D: c.Direction,
		P: c.Port, I: c.IranIP, K: c.KharejIP, S: c.PSK, Pr: c.Proto, It: c.ICMPType,
		Ic: c.ICMPCode, Ir: c.ICMPRply, Sn: c.Subnet, M: c.MTU, Dd: c.DNSDomain, Mx: c.Mux})
	return prefix + base64.RawURLEncoding.EncodeToString(b), nil
}

// Decode is run on kharej. The code comes from outside, so the result is
// validated like any other config before it is returned.
func Decode(s, name string) (*config.Config, error) {
	s = strings.Join(strings.Fields(s), "")
	s = strings.TrimPrefix(s, prefix)
	b, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
	if err != nil {
		return nil, errors.New("not a pair code")
	}
	var p code
	if err := json.Unmarshal(b, &p); err != nil || p.V != 1 {
		return nil, errors.New("unrecognised pair code")
	}
	if name == "" {
		name = p.N
	}
	c := &config.Config{Name: name, Role: config.RoleKharej, Transport: p.T, Carrier: p.C,
		Direction: p.D, Port: p.P, IranIP: p.I, KharejIP: p.K, PSK: p.S, Proto: p.Pr,
		ICMPType: p.It, ICMPCode: p.Ic, ICMPRply: p.Ir, Subnet: p.Sn, MTU: p.M,
		DNSDomain: p.Dd, Mux: p.Mx}
	c.Defaults()
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return c, nil
}
