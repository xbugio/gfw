package main

import (
	"crypto/tls"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

func resolveDNS(w dns.ResponseWriter, m *dns.Msg) {
	defer w.Close()

	// 不常规的question数量，或者question不是A记录查询，转给本地DNS
	if len(m.Question) != 1 || m.Question[0].Qtype != dns.TypeA {
		resolveLocalDNS(w, m)
		return
	}

	// 判断是否是static mapping
	question := m.Question[0]
	domain := strings.TrimSuffix(question.Name, ".")
	ip, exists := config.DNS.StaticDomainMapping[domain]
	if exists {
		parsedIP := net.ParseIP(ip)
		if parsedIP == nil {
			resolveLocalDNS(w, m)
			return
		}

		answer := &dns.A{
			Hdr: dns.RR_Header{
				Name:   question.Name,
				Rrtype: question.Qtype,
				Class:  question.Qclass,
				Ttl:    600,
			},
			A: parsedIP.To4(),
		}

		replyMsg := new(dns.Msg)
		replyMsg.SetReply(m)
		replyMsg.Answer = []dns.RR{answer}
		w.WriteMsg(replyMsg)
		return
	}

	// 判断是否是keyword
	for _, kw := range config.DNS.TLSDomainKeyword {
		if strings.Contains(question.Name, kw) {
			resolveTLSDNS(w, m)
			return
		}
	}

	// 都不是，则转发给本地服务器
	resolveLocalDNS(w, m)
}

func resolveLocalDNS(w dns.ResponseWriter, m *dns.Msg) {
	r, _, err := localDNSClient.Exchange(m, config.DNS.LocalDNS)
	if err != nil {
		return
	}
	w.WriteMsg(r)
}

func resolveTLSDNS(w dns.ResponseWriter, m *dns.Msg) {
	conn, err := socks5Client.DialTimeout("tcp", config.DNS.TLSDNS, time.Second*2)
	if err != nil {
		return
	}
	defer conn.Close()
	tlsConn := tls.Client(conn, tlsConfig)
	dnsConn := &dns.Conn{Conn: tlsConn}
	r, _, err := tlsDNSClient.ExchangeWithConn(m, dnsConn)
	if err != nil {
		return
	}
	w.WriteMsg(r)
}
