package main

import (
	"bytes"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"strings"
)

func setupFW() error {
	_, port, err := net.SplitHostPort(config.RedirListen)
	if err != nil {
		return err
	}

	if config.Nft {
		nftTpl := `
table ip gfw {
	set gfw_mynet_exclude {
		type ipv4_addr
		flags interval
		%v
	}

	set gfw_mynet {
		type ipv4_addr
		flags interval
		%v
	}

	set gfw_mymac {
		type ether_addr
		%v
	}

	set gfw_geoipcn {
		type ipv4_addr
		flags interval
		%v
	}

	set gfw_geoipcn_exclude {
		type ipv4_addr
		flags interval
		%v
	}

	chain GFW_HOOK_ALL {
		type nat hook prerouting priority dstnat - 1; policy accept;
		ip saddr @gfw_mynet_exclude accept
		ip saddr @gfw_mynet goto GFW
		ether saddr @gfw_mymac goto GFW
	}

	chain GFW {
		ip daddr @gfw_geoipcn_exclude goto GFW_REDIRECT
		ip daddr @gfw_geoipcn accept
		goto GFW_REDIRECT
	}

	chain GFW_REDIRECT {
		ip protocol tcp redirect to :%v
		accept
	}
}`
		nftContent := fmt.Sprintf(nftTpl,
			getElementString(config.MyNetExclude),
			getElementString(config.MyNet),
			getElementString(config.MyMAC),
			getElementString(config.CNIP),
			getElementString(config.CNIPExclude),
			port)

		err = os.WriteFile("/tmp/gfw.nft", []byte(nftContent), 0644)
		if err != nil {
			return err
		}
		if !config.Debug {
			defer os.Remove("/tmp/gfw.nft")
		}
		excuteCMD("nft -f /tmp/gfw.nft")
	} else {
		cmd := "ipset create gfw_mynet hash:net hashsize 4096 maxelem 65535\n"
		cmd += "ipset create gfw_mymac hash:mac hashsize 4096 maxelem 65535\n"
		cmd += "ipset create gfw_geoipcn hash:net hashsize 65535 maxelem 65535\n"

		cmd += "iptables -t nat -N GFW_HOOK_ALL\n"
		cmd += "iptables -t nat -N GFW\n"
		cmd += "iptables -t nat -N GFW_REDIRECT\n"

		cmd += "iptables -t nat -A GFW_HOOK_ALL -m set --match-set gfw_mynet src -j GFW\n"
		cmd += "iptables -t nat -A GFW_HOOK_ALL -m set --match-set gfw_mymac src -j GFW\n"

		cmd += "iptables -t nat -A GFW -m set --match-set gfw_geoipcn dst -j RETURN\n"
		cmd += "iptables -t nat -A GFW -p tcp -m multiport --dports 22,80,443 -j REDIRECT --to-ports " + port + "\n"

		cmd += "iptables -t nat -A PREROUTING -j GFW_HOOK_ALL\n"

		excuteCMD(cmd)

		ipsetContent := ""
		for _, ip := range config.CNIP {
			ipsetContent += "add gfw_geoipcn " + ip + "\n"
		}

		for _, ip := range config.CNIPExclude {
			ipsetContent += "add gfw_geoipcn " + ip + " nomatch\n"
		}

		for _, ip := range config.MyNet {
			ipsetContent += "add gfw_mynet " + ip + "\n"
		}

		for _, ip := range config.MyNetExclude {
			ipsetContent += "add gfw_mynet " + ip + "nomatch\n"
		}

		for _, mac := range config.MyMAC {
			ipsetContent += "add gfw_mymac " + mac + "\n"
		}

		err = os.WriteFile("/tmp/gfw.ipset", []byte(ipsetContent), 0644)
		if err != nil {
			return err
		}
		if !config.Debug {
			defer os.Remove("/tmp/gfw.ipset")
		}
		excuteCMD("ipset restore -f /tmp/gfw.ipset")
	}
	return nil
}

func destoryFW() {

	cmd := ""
	if config.Nft {
		cmd = "nft 'delete table ip gfw'\n"
	} else {
		cmd = "iptables -t nat -F GFW\n"
		cmd += "iptables -t nat -F GFW_HOOK_ALL\n"
		cmd += "iptables -t nat -D PREROUTING -j GFW_HOOK_ALL\n"
		cmd += "iptables -t nat -X GFW\n"
		cmd += "iptables -t nat -X GFW_HOOK_ALL\n"
		cmd += "ipset destroy gfw_mynet\n"
		cmd += "ipset destroy gfw_mymac\n"
		cmd += "ipset destroy gfw_geoipcn\n"
	}

	excuteCMD(cmd)
}

func excuteCMD(cmdStr string) {
	cmd := exec.Command("/bin/sh")
	cmd.Stdin = strings.NewReader(cmdStr)

	var (
		stdoutBuffer *bytes.Buffer
		stderrBuffer *bytes.Buffer
	)

	if config.Debug {
		stdoutBuffer = new(bytes.Buffer)
		stderrBuffer = new(bytes.Buffer)
		cmd.Stdout = stdoutBuffer
		cmd.Stderr = stderrBuffer
	}

	cmd.Run()

	if config.Debug {
		log.Println("command: ", cmdStr)
		log.Println("stdout: ", stdoutBuffer.String())
		log.Println("stderr: ", stderrBuffer.String())
	}
}

func getElementString(elements []string) string {
	if len(elements) == 0 {
		return ""
	}
	return "elements = {\n" +
		strings.Join(elements, ",") +
		"\n}\n"
}
