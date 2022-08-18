package client

import (
	"encoding/binary"
	"errors"
	"net"
	"strconv"
	"time"
)

// Client socks5 客户端实现
type Client struct {
	// Server socks5服务器地址
	Server string
	// Username socks5认证用户名，空为不认证
	Username string
	//Password socks5认证密码
	Password string
	//ConnectionTimeout 连接超时时间
	ConnectionTimeout time.Duration
	//ReadTimeout 读超时时间
	ReadTimeout time.Duration
	//WriteTimeout 写超时时间
	WriteTimeout time.Duration
}

// Conn 同net.Conn
type Conn = net.Conn

// Addr 等价net.Addr
type Addr = net.Addr

var (
	// ErrWrongNetworkType 错误的network值
	ErrWrongNetworkType = errors.New("wrong network type")
	// ErrServerClosed socks5服务器异常
	ErrServerClosed = errors.New("socks5 server close the connection")
	// ErrAuthFailed socks5认证失败
	ErrAuthFailed = errors.New("failed to auth")
)

// DialTimeout 设置连接超时后发起proxy代理连接, network允许的值，tcp、udp
func (c *Client) DialTimeout(network string, address string, timeout time.Duration) (Conn, error) {
	c.ConnectionTimeout = timeout
	return c.Dial(network, address)
}

// Dial 发起proxy代理连接, network允许的值，tcp、udp
func (c *Client) Dial(network string, address string) (Conn, error) {

	var (
		conn net.Conn
		err  error
	)

	if network != "tcp" && network != "udp" {
		return nil, ErrWrongNetworkType
	}

	var (
		// atype 0x01 ipv4, 0x03 domain, 0x04 ipv6
		atype   byte
		dstaddr []byte
		dstport []byte
	)

	host, portStr, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}

	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, err
	}

	ip := net.ParseIP(host)

	if ip == nil {
		atype = 0x03
		dstaddr = []byte{byte(len(host))}
		dstaddr = append(dstaddr, []byte(host)...)
	} else {
		if ip.DefaultMask() == nil {
			atype = 0x04
			dstaddr = ip
		} else {
			atype = 0x01
			dstaddr = ip.To4()[:4]
		}
	}
	dstport = []byte{0x00, 0x00}
	binary.BigEndian.PutUint16(dstport, uint16(port))

	if c.ConnectionTimeout <= 0 {
		c.ConnectionTimeout = time.Second * 3
	}

	if c.ReadTimeout <= 0 {
		c.ReadTimeout = time.Second * 3
	}

	if c.WriteTimeout <= 0 {
		c.WriteTimeout = time.Second * 3
	}

	conn, err = net.DialTimeout("tcp", c.Server, c.ConnectionTimeout)
	if err != nil {
		return nil, err
	}

	// 默认，版本5，1种认证方式，即无认证
	data := []byte{0x05, 0x01, 0x00}
	// 若设置了用户名，则增加一种用户名认证方式
	if c.Username != "" && c.Password != "" {
		data[1]++
		data = append(data, 0x02)
	}

	err = conn.SetWriteDeadline(time.Now().Add(c.WriteTimeout))
	if err != nil {
		conn.Close()
		return nil, err
	}

	_, err = conn.Write(data)
	if err != nil {
		conn.Close()
		return nil, err
	}

	err = conn.SetReadDeadline(time.Now().Add(c.ReadTimeout))
	if err != nil {
		conn.Close()
		return nil, err
	}

	n, err := conn.Read(data)
	if err != nil {
		conn.Close()
		return nil, err
	}
	if n != 2 {
		conn.Close()
		return nil, ErrServerClosed
	}
	if data[0] != 0x05 || data[1] == 0xff {
		conn.Close()
		return nil, ErrServerClosed
	}

	// socks5服务器返回需要密码认证
	if data[1] == 0x02 {
		data = []byte{0x05, uint8(len(c.Username))}
		data = append(data, []byte(c.Username)...)
		data = append(data, uint8(len(c.Password)))
		data = append(data, []byte(c.Password)...)

		err = conn.SetWriteDeadline(time.Now().Add(c.WriteTimeout))
		if err != nil {
			conn.Close()
			return nil, err
		}

		_, err = conn.Write(data)
		if err != nil {
			conn.Close()
			return nil, err
		}

		err = conn.SetReadDeadline(time.Now().Add(c.ReadTimeout))
		if err != nil {
			conn.Close()
			return nil, err
		}
		n, err = conn.Read(data)
		if err != nil {
			conn.Close()
			return nil, err
		}

		if n != 2 || data[0] != 0x05 {
			conn.Close()
			return nil, ErrServerClosed
		}

		if data[1] != 0x00 {
			return nil, ErrAuthFailed
		}
	}

	// 与socks5服务器握手完毕，准备向目标服务器发起连接
	if network == "tcp" {
		data = []byte{0x05, 0x01, 0x00, atype}
		data = append(data, dstaddr...)
		data = append(data, dstport...)
	} else {
		data = []byte{0x05, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	}

	err = conn.SetWriteDeadline(time.Now().Add(c.WriteTimeout))
	if err != nil {
		conn.Close()
		return nil, err
	}

	_, err = conn.Write(data)
	if err != nil {
		conn.Close()
		return nil, err
	}

	err = conn.SetReadDeadline(time.Now().Add(c.ReadTimeout))
	if err != nil {
		conn.Close()
		return nil, err
	}

	data = make([]byte, 512)
	n, err = conn.Read(data)
	if err != nil {
		conn.Close()
		return nil, err
	}
	if n < 2 || data[1] != 0x00 {
		conn.Close()
		return nil, ErrServerClosed
	}

	conn.SetDeadline(time.Time{})
	var warp Conn
	if network == "tcp" {
		warp = &TCPConn{
			conn: conn,
		}
	} else {
		head := []byte{0x00, 0x00, 0x00}
		head = append(head, atype)
		head = append(head, dstaddr...)
		head = append(head, dstport...)
		warp = &UDPConn{
			conn: conn,
			head: head,
		}
	}
	return warp, nil
}
