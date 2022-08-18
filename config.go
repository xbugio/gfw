package main

import (
	"encoding/json"
	"os"
)

type Config struct {
	RedirListen  string       `json:"redir_listen"`
	Socks5       Socks5Config `json:"socks5"`
	Nft          bool         `json:"nft"`
	MyMAC        []string     `json:"mymac"`
	MyNet        []string     `json:"mynet"`
	MyNetExclude []string     `json:"mynet_exclude"`
	DNS          DNSConfig    `json:"dns"`
	CNIP         []string     `json:"cnip"`
	CNIPExclude  []string     `json:"cnip_exclude"`
	Debug        bool         `json:"debug"`
}

type Socks5Config struct {
	Addr     string `json:"addr"`
	Username string `json:"username"`
	Password string `json:"password"`
}

type DNSConfig struct {
	Listen              string            `json:"listen"`
	LocalDNS            string            `json:"local_dns"`
	TLSDNS              string            `json:"tls_dns"`
	StaticDomainMapping map[string]string `json:"static_domain_mapping"`
	TLSDomainKeyword    []string          `json:"tls_domain_keyword"`
}

func parseConfig(filename string) (*Config, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	config := new(Config)
	err = json.NewDecoder(file).Decode(config)
	if err != nil {
		return nil, err
	}
	return config, nil
}
