package client

import (
	"net"
	"time"
)

// UDPConn socks5 tcp连接
type UDPConn struct {
	conn net.Conn
	head []byte
}

// Read 从proxy中读取数据
func (c *UDPConn) Read(b []byte) (n int, err error) {
	return c.conn.Read(b)
}

// Write 往proxy中写数据
func (c *UDPConn) Write(b []byte) (n int, err error) {
	n1, err := c.conn.Write(c.head)
	if err != nil {
		return n1, err
	}
	n2, err := c.conn.Write(b)
	n = n1 + n2
	return n, err
}

// Close 关闭proxy连接
func (c *UDPConn) Close() error {
	return c.conn.Close()
}

// LocalAddr 返回本地地址
func (c *UDPConn) LocalAddr() Addr {
	return c.conn.LocalAddr()
}

// RemoteAddr 返回远程地址
func (c *UDPConn) RemoteAddr() Addr {
	return c.conn.RemoteAddr()
}

// SetDeadline 设置读写超时时间，零值为不限
func (c *UDPConn) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

// SetReadDeadline 设定该连接的读操作deadline，参数t为零值表示不设置期限
func (c *UDPConn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

// SetWriteDeadline 设定该连接的写操作deadline，参数t为零值表示不设置期限
func (c *UDPConn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}
