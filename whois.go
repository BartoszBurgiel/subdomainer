package subdomainer

import (
	"bufio"
	"math/big"
	"net"
	"strings"
	"sync"
)

type whoisResult struct {
	Ip    string  `json:"ip"`
	Whois network `json:"whois"`
}

// network defines the network in which an IP adress resides
type network struct {
	Inetnum     string `json:"inetnum"`
	Netname     string `json:"netname"`
	Country     string `json:"country"`
	Description string `json:"description"`
	Org         string `json:"org"`
}

// observedNetworks stores all of the networks which have been resolved already
var observedNetworks *sync.Map = &sync.Map{}

var whoisMutex *sync.Mutex = &sync.Mutex{}

// isIPInRange returns whether an ip address, for example 1.2.3.4
// is in the inetnum ip address range returned from whois
// for example: '1.2.3.0 = 1.2.3.255'
func isIPInRange(ip, network string) bool {
	ips := strings.Split(network, " - ")
	if len(ips) != 2 {
		return false
	}

	startIP := net.ParseIP(ips[0])
	endIP := net.ParseIP(ips[1])
	if startIP == nil || endIP == nil {
		return false
	}

	ipAddr := net.ParseIP(ip)
	if ipAddr == nil {
		return false
	}

	ip1 := startIP.To16()
	ip2 := endIP.To16()

	ip1int := big.NewInt(0).SetBytes(ip1)
	ip2int := big.NewInt(0).SetBytes(ip2)

	ipAddrInt := big.NewInt(0).SetBytes(ipAddr)

	if ip1int.Int64() < ipAddrInt.Int64() && ipAddrInt.Int64() < ip2int.Int64() {
		return true
	}
	return false
}

// resolveWhoisOfIP checks if the network of the ip
// is already in the cache, otherwise it resolves it
// and puts it to the cache
func resolveWhoisOfIP(ip string) whoisResult {
	if net.ParseIP(ip).IsPrivate() {
		return whoisResult{
			Ip: ip,
			Whois: network{
				Description: "Private IP",
			},
		}
	}

	whoisMutex.Lock()
	defer whoisMutex.Unlock()
	netwrk := network{}
	// check if IP is in the cache
	observedNetworks.Range(func(key, value any) bool {
		if isIPInRange(ip, key.(string)) {
			netwrk = value.(network)
			return false
		}
		return true
	})

	if netwrk.Inetnum != "" {
		return whoisResult{
			Ip:    ip,
			Whois: netwrk,
		}
	}

	res := whoisQuery(ip)
	netwrk = parseWhoisData(res)
	observedNetworks.Store(netwrk.Inetnum, netwrk)
	observedNetworks.Range(func(key, value any) bool {
		return true
	})
	return whoisResult{
		Ip:    ip,
		Whois: netwrk,
	}
}

func whoisQuery(ip string) string {
	server := "whois.ripe.net"
	conn, err := net.Dial("tcp", server+":43")
	if err != nil {
		return ""
	}
	defer conn.Close()

	_, err = conn.Write([]byte(ip + "\r\n"))
	if err != nil {
		return ""
	}

	whoisData := ""
	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		whoisData += scanner.Text() + "\n"
	}

	if err := scanner.Err(); err != nil {
		return ""
	}

	return whoisData
}

func parseWhoisData(data string) network {
	scanner := bufio.NewScanner(strings.NewReader(data))
	n := network{}
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "inetnum:") {
			n.Inetnum = strings.TrimSpace(strings.TrimPrefix(line, "inetnum:"))
		}
		if strings.HasPrefix(line, "netname:") {
			n.Netname = strings.TrimSpace(strings.TrimPrefix(line, "netname:"))
		}
		if strings.HasPrefix(line, "country:") {
			n.Country = strings.TrimSpace(strings.TrimPrefix(line, "country:"))
		}
		if strings.HasPrefix(line, "org:") {
			n.Org = strings.TrimSpace(strings.TrimPrefix(line, "org:"))
		}
		if strings.HasPrefix(line, "descr:") {
			n.Org = strings.TrimSpace(strings.TrimPrefix(line, "descr:"))
		}
	}

	return n
}
