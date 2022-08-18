package main

import (
	"io"
	"net"
	"os"
	"syscall"
	"time"
	"unsafe"
)

func handleConn(conn *net.TCPConn) {
	originAddr, err := getOriginalDST(conn)
	if err != nil {
		conn.Close()
		return
	}

	originAddrStr := originAddr.String()
	if originAddrStr == conn.LocalAddr().String() {
		conn.Close()
		return
	}

	proxyedConn, err := socks5Client.DialTimeout("tcp", originAddrStr, time.Second*5)
	if err != nil {
		conn.Close()
		return
	}

	go func() {
		io.Copy(conn, proxyedConn)
		proxyedConn.Close()
		conn.Close()
	}()
	io.Copy(proxyedConn, conn)
	proxyedConn.Close()
	conn.Close()
}

const (
	// SO_ORIGINAL_DST is a Linux getsockopt optname.
	SO_ORIGINAL_DST = 80

	// IP6T_SO_ORIGINAL_DST a Linux getsockopt optname.
	IP6T_SO_ORIGINAL_DST = 80
)

func getsockopt(s int, level int, optname int, optval unsafe.Pointer, optlen *uint32) (err error) {
	_, _, e := syscall.Syscall6(
		syscall.SYS_GETSOCKOPT, uintptr(s), uintptr(level), uintptr(optname),
		uintptr(optval), uintptr(unsafe.Pointer(optlen)), 0)
	if e != 0 {
		return e
	}
	return
}

// getOriginalDST retrieves the original destination address from
// NATed connection.  Currently, only Linux iptables using DNAT/REDIRECT
// is supported.  For other operating systems, this will just return
// conn.LocalAddr().
//
// Note that this function only works when nf_conntrack_ipv4 and/or
// nf_conntrack_ipv6 is loaded in the kernel.
func getOriginalDST(conn *net.TCPConn) (*net.TCPAddr, error) {
	f, err := conn.File()
	if err != nil {
		return nil, err
	}
	defer f.Close()

	fd := int(f.Fd())
	// revert to non-blocking mode.
	// see http://stackoverflow.com/a/28968431/1493661
	if err = syscall.SetNonblock(fd, true); err != nil {
		return nil, os.NewSyscallError("setnonblock", err)
	}

	isV6 := conn.LocalAddr().(*net.TCPAddr).IP.To4() == nil
	if isV6 {
		var addr syscall.RawSockaddrInet6
		len := uint32(unsafe.Sizeof(addr))
		err = getsockopt(fd, syscall.IPPROTO_IPV6, IP6T_SO_ORIGINAL_DST,
			unsafe.Pointer(&addr), &len)
		if err != nil {
			return nil, os.NewSyscallError("getsockopt", err)
		}
		ip := make([]byte, 16)
		copy(ip, addr.Addr[:])
		pb := *(*[2]byte)(unsafe.Pointer(&addr.Port))
		return &net.TCPAddr{
			IP:   ip,
			Port: int(pb[0])*256 + int(pb[1]),
		}, nil
	}

	// IPv4
	var addr syscall.RawSockaddrInet4
	len := uint32(unsafe.Sizeof(addr))
	err = getsockopt(fd, syscall.IPPROTO_IP, SO_ORIGINAL_DST,
		unsafe.Pointer(&addr), &len)
	if err != nil {
		return nil, os.NewSyscallError("getsockopt", err)
	}
	ip := make([]byte, 4)
	copy(ip, addr.Addr[:])
	pb := *(*[2]byte)(unsafe.Pointer(&addr.Port))
	return &net.TCPAddr{
		IP:   ip,
		Port: int(pb[0])*256 + int(pb[1]),
	}, nil
}
