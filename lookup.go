package subdomainer

import (
	"net"
)

// dnsLookup returns the IP of the prodided domain
func dnsLookup(dom string) string {
	res, _ := net.LookupIP(dom)
	if len(res) > 0 {
		return res[0].String()
	}
	return ""
}
