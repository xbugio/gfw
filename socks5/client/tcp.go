package client

import (
	"net"
	"time"
)

// TCPConn socks5 tcp连接
type TCPConn struct {
	conn net.Conn
}

// Read 从proxy中读取数据
func (c *TCPConn) Read(b []byte) (n int, err error) {
	return c.conn.Read(b)
}

// Write 往proxy中写数据
func (c *TCPConn) Write(b []byte) (n int, err error) {
	return c.conn.Write(b)
}

// Close 关闭proxy连接
func (c *TCPConn) Close() error {
	return c.conn.Close()
}

// LocalAddr 返回本地地址
func (c *TCPConn) LocalAddr() Addr {
	return c.conn.LocalAddr()
}

// RemoteAddr 返回远程地址
func (c *TCPConn) RemoteAddr() Addr {
	return c.conn.RemoteAddr()
}

// SetDeadline 设置读写超时时间，零值为不限
func (c *TCPConn) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

// SetReadDeadline 设定该连接的读操作deadline，参数t为零值表示不设置期限
func (c *TCPConn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

// SetWriteDeadline 设定该连接的写操作deadline，参数t为零值表示不设置期限
func (c *TCPConn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}
