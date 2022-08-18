package main

import (
	"crypto/tls"
	"flag"
	"gfw/socks5/client"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/miekg/dns"
)

var (
	config         *Config
	socks5Client   *client.Client
	dnsServer      *dns.Server
	localDNSClient *dns.Client
	tlsDNSClient   *dns.Client
	tlsConfig      *tls.Config = &tls.Config{InsecureSkipVerify: true}
)

func main() {
	var err error

	// 1. load configuration
	var configFilename string
	flag.StringVar(&configFilename, "config", "config.json", "config filename")
	flag.Parse()
	config, err = parseConfig(configFilename)
	if err != nil {
		log.Fatal(err)
	}

	// 2. init socks5 client
	socks5Client = &client.Client{
		Server:            config.Socks5.Addr,
		Username:          config.Socks5.Username,
		Password:          config.Socks5.Password,
		ConnectionTimeout: time.Second * 3,
		ReadTimeout:       time.Second * 3,
		WriteTimeout:      time.Second * 3,
	}

	// 3. init dns router
	localDNSClient = &dns.Client{
		Net: "udp",
	}
	tlsDNSClient = &dns.Client{
		Net: "tcp-tls",
	}
	dnsServer = &dns.Server{
		Addr:    config.DNS.Listen,
		Net:     "udp",
		Handler: dns.HandlerFunc(resolveDNS),
	}

	go func() {
		if err := dnsServer.ListenAndServe(); err != nil {
			log.Fatal(err)
		}
	}()

	// 4. init redirect service
	laddr, err := net.ResolveTCPAddr("tcp", config.RedirListen)
	if err != nil {
		log.Fatal(err)
	}
	listener, err := net.ListenTCP("tcp", laddr)
	if err != nil {
		log.Fatal(err)
	}
	go func() {
		for {
			conn, err := listener.AcceptTCP()
			if err != nil {
				log.Fatal(err)
			}
			go handleConn(conn)
		}
	}()

	destoryFW()
	if err := setupFW(); err != nil {
		log.Fatal(err)
	}

	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	<-c
	destoryFW()
}
