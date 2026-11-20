package stream

import (
	"net"
	"syscall"
)

// tcpCongestion is TCP_CONGESTION; not in the syscall package on all versions.
const tcpCongestion = 13

// SetCongestion sets the TCP congestion control for one connection (Linux),
// e.g. "bbr" or "cubic". It touches only this socket, not the whole system,
// and silently does nothing for a non-TCP conn or an unknown algorithm.
func SetCongestion(c net.Conn, cc string) {
	if cc == "" {
		return
	}
	tc, ok := c.(*net.TCPConn)
	if !ok {
		return
	}
	raw, err := tc.SyscallConn()
	if err != nil {
		return
	}
	_ = raw.Control(func(fd uintptr) {
		_ = syscall.SetsockoptString(int(fd), syscall.IPPROTO_TCP, tcpCongestion, cc)
	})
}
