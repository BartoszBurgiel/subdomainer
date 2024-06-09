package subdomainer

import (
	"net"
	"strings"
)

// dnsLookup returns the IP of the prodided domain
func dnsLookup(dom string) []whoisResult {
	res, _ := net.LookupIP(dom)
	if len(res) == 0 {
		return []whoisResult{}
	}
	addresses := []whoisResult{}
	for i := 0; i < len(res); i++ {
		if strings.Contains(res[i].String(), ":") {
			return addresses
		}

		whois := resolveWhoisOfIP(res[i].String())
		addresses = append(addresses, whois)
	}
	return addresses
}
