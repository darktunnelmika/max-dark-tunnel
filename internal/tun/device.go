// Package tun implements the layer-3 transports: a tun device on each side,
// with packets carried over raw IP, ICMP, UDP, TCP or DNS.
package tun

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"unsafe"
)

const (
	iffTun   = 0x0001
	iffNoPI  = 0x1000
	tunSetIF = 0x400454ca
)

// Open creates the tun device and gives it its /30 address.
func Open(name, local string, mtu int) (*os.File, error) {
	// Configure the fd before handing it to the runtime poller: adding a tun
	// fd to epoll before TUNSETIFF fails and leaves reads "not pollable".
	fd, err := syscall.Open("/dev/net/tun", syscall.O_RDWR|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open /dev/net/tun: %w", err)
	}
	var req [40]byte
	copy(req[:16], name)
	*(*uint16)(unsafe.Pointer(&req[16])) = iffTun | iffNoPI
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), tunSetIF, uintptr(unsafe.Pointer(&req[0]))); e != 0 {
		syscall.Close(fd)
		return nil, fmt.Errorf("TUNSETIFF %s: %v", name, e)
	}
	if err := syscall.SetNonblock(fd, true); err != nil {
		syscall.Close(fd)
		return nil, err
	}
	f := os.NewFile(uintptr(fd), "/dev/net/tun")
	cmds := [][]string{
		{"addr", "flush", "dev", name},
		{"addr", "add", local + "/30", "dev", name},
		{"link", "set", "dev", name, "mtu", fmt.Sprint(mtu), "up"},
	}
	for _, a := range cmds {
		if out, err := exec.Command("ip", a...).CombinedOutput(); err != nil {
			f.Close()
			return nil, fmt.Errorf("ip %s: %v %s", strings.Join(a, " "), err, out)
		}
	}
	return f, nil
}
