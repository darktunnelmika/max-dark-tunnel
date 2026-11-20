// mdt - Max Dark Tunnel core.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/darktunnelmika/max-dark-tunnel/internal/config"
	"github.com/darktunnelmika/max-dark-tunnel/internal/pair"
	"github.com/darktunnelmika/max-dark-tunnel/internal/status"
	"github.com/darktunnelmika/max-dark-tunnel/internal/stream"
	"github.com/darktunnelmika/max-dark-tunnel/internal/tun"
)

var version = "dev"

const usage = `mdt - Max Dark Tunnel core %s

  mdt run    -c FILE              run a tunnel (systemd does this)
  mdt new    [flags] -o FILE      write a new iran or kharej config
  mdt pair   -c FILE              print the pair code of an iran config
  mdt join   -code CODE -o FILE   write the kharej config from a pair code
  mdt check  -c FILE              validate a config
  mdt status -c FILE              print live status as key=value lines
  mdt psk                         print a fresh pre-shared key
  mdt version
`

func main() {
	if len(os.Args) < 2 {
		fmt.Printf(usage, version)
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]
	var err error
	switch cmd {
	case "run":
		err = cmdRun(args)
	case "new":
		err = cmdNew(args)
	case "pair":
		err = cmdPair(args)
	case "join":
		err = cmdJoin(args)
	case "check":
		err = cmdCheck(args)
	case "status":
		err = cmdStatus(args)
	case "psk":
		fmt.Println(config.NewPSK())
	case "version", "-v", "--version":
		fmt.Println(version)
	default:
		fmt.Printf(usage, version)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func loadFlag(name string, args []string) (*config.Config, error) {
	fs := flag.NewFlagSet(name, flag.ExitOnError)
	path := fs.String("c", "", "config file")
	_ = fs.Parse(args)
	if *path == "" {
		return nil, fmt.Errorf("-c is required")
	}
	return config.Load(*path)
}

func cmdRun(args []string) error {
	cfg, err := loadFlag("run", args)
	if err != nil {
		return err
	}
	status.Setup(cfg.LogFile)
	desc := cfg.Transport
	if cfg.Transport == config.TransportTun {
		desc += "/" + cfg.Carrier
	}
	log.Printf("max dark tunnel %s - %s - %s side - %s %s", version, cfg.Name, cfg.Role, desc, cfg.Direction)
	st := status.New(cfg.StatusFile, desc)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	switch cfg.Transport {
	case config.TransportTCP:
		err = stream.Run(ctx, cfg, stream.Smux(cfg.PSK, cfg.IsIran()), st)
	case config.TransportSSH:
		err = stream.Run(ctx, cfg, stream.SSH(cfg.PSK), st)
	case config.TransportTun, config.TransportDNS:
		err = tun.Run(ctx, cfg, st)
	}
	if err != nil {
		log.Printf("fatal: %v", err)
	}
	return err
}

func cmdNew(args []string) error {
	fs := flag.NewFlagSet("new", flag.ExitOnError)
	c := &config.Config{}
	out := fs.String("o", "", "output file")
	fs.StringVar(&c.Name, "name", "", "tunnel name")
	fs.StringVar(&c.Role, "role", "iran", "iran | kharej")
	fs.StringVar(&c.Transport, "transport", "tcp", "tcp | tun | dns | ssh")
	fs.StringVar(&c.Carrier, "carrier", "", "tun carrier: mdtp | icmp | tcp | udp")
	fs.StringVar(&c.Direction, "direction", "", "reverse | direct")
	fs.IntVar(&c.Port, "port", 0, "carrier port")
	fs.StringVar(&c.IranIP, "iran-ip", "", "iran public ip")
	fs.StringVar(&c.KharejIP, "kharej-ip", "", "kharej public ip")
	fs.StringVar(&c.BindIP, "bind", "", "local bind address")
	fs.StringVar(&c.PSK, "psk", "", "pre-shared key (generated if empty)")
	fs.IntVar(&c.Proto, "proto", 0, "mdtp: ip protocol number")
	fs.IntVar(&c.ICMPType, "icmp-type", 0, "icmp: type iran sends")
	fs.IntVar(&c.ICMPRply, "icmp-reply", 0, "icmp: type kharej sends")
	fs.IntVar(&c.ICMPCode, "icmp-code", 0, "icmp: code")
	fs.IntVar(&c.Subnet, "subnet", 0, "tun: 10.20.<n>.0/30")
	fs.IntVar(&c.MTU, "mtu", 0, "tun mtu")
	fs.StringVar(&c.DNSDomain, "dns-domain", "", "dns: query domain")
	fs.IntVar(&c.Mux, "mux", 0, "parallel carrier connections")
	fs.StringVar(&c.TCPPorts, "tcp-ports", "", "iran: 443,8080>80,...")
	fs.StringVar(&c.UDPPorts, "udp-ports", "", "iran: udp ports")
	_ = fs.Parse(args)
	if *out == "" {
		return fmt.Errorf("-o is required")
	}
	if c.PSK == "" {
		c.PSK = config.NewPSK()
	}
	c.Defaults()
	if err := c.Validate(); err != nil {
		return err
	}
	return c.Save(*out)
}

func cmdPair(args []string) error {
	cfg, err := loadFlag("pair", args)
	if err != nil {
		return err
	}
	s, err := pair.Encode(cfg)
	if err != nil {
		return err
	}
	fmt.Println(s)
	return nil
}

func cmdJoin(args []string) error {
	fs := flag.NewFlagSet("join", flag.ExitOnError)
	code := fs.String("code", "", "pair code")
	name := fs.String("name", "", "override tunnel name")
	out := fs.String("o", "", "output file")
	_ = fs.Parse(args)
	if *code == "" || *out == "" {
		return fmt.Errorf("-code and -o are required")
	}
	c, err := pair.Decode(*code, *name)
	if err != nil {
		return err
	}
	if err := c.Save(*out); err != nil {
		return err
	}
	fmt.Println(c.Name)
	return nil
}

func cmdCheck(args []string) error {
	cfg, err := loadFlag("check", args)
	if err != nil {
		return err
	}
	fmt.Printf("ok: %s (%s, %s)\n", cfg.Name, cfg.Role, cfg.Transport)
	return nil
}

func cmdStatus(args []string) error {
	cfg, err := loadFlag("status", args)
	if err != nil {
		return err
	}
	b, err := os.ReadFile(cfg.StatusFile)
	if err != nil {
		fmt.Println("state=stopped")
		return nil
	}
	var m struct {
		State     string `json:"state"`
		Since     int64  `json:"since"`
		Peer      string `json:"peer"`
		Sessions  int    `json:"sessions"`
		Transport string `json:"transport"`
		Rx, Tx    uint64
		Updated   int64 `json:"updated"`
	}
	_ = json.Unmarshal(b, &m)
	if time.Since(time.Unix(m.Updated, 0)) > 20*time.Second {
		m.State = "stale"
	}
	fmt.Printf("state=%s\npeer=%s\nsessions=%d\ntransport=%s\nuptime=%s\nrx=%s\ntx=%s\n",
		m.State, m.Peer, m.Sessions, m.Transport,
		time.Since(time.Unix(m.Since, 0)).Truncate(time.Second), status.Human(m.Rx), status.Human(m.Tx))
	return nil
}
