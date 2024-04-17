package subdomainer

import (
	"fmt"
	"strings"
	"sync"
)

// Recurse over all found subdomains and start the process again
func Recurse(wg *sync.WaitGroup) {

	thirdLvl := getSubdomainsFromAll()
	fmt.Println("now recursing over", thirdLvl)
	for _, v := range thirdLvl {
		fmt.Println("so now about to examine this..i.")
		fmt.Println(v)
		if isWildcardSubdomain(v) {
			fmt.Println("sadly this is a wildcard subdomain.... skipping!!!")
			continue
		}
		examineSubdomain(v, wg)
	}
	fmt.Println("recursing finished...")
}

func examineSubdomain(domain string, wg *sync.WaitGroup) {
	fmt.Println("further examinig of ", domain)
	CrawlAlienvault(domain, wg)
	CrawlRapidDNS(domain, wg)
	CrawlDNSDumpster(domain, wg)
	CrawlHackertarget(domain, wg)
	ScanLimit = 150
	wg.Add(1)
	fmt.Println("after wait and before crawling the query word list")
	QueryWordlist("../words/top_dns.words", domain, wg)

}

func getSubdomainsFromAll() []string {
	subs := make(map[string]bool)
	res := []string{}
	Subdomains.Range(func(key, value any) bool {
		subdomain := key.(string)
		// the subdomain sequence must contain at least
		// three dots in order to have at least one sub-subdomain
		// => "subd.subd.domain.com"
		if strings.Count(subdomain, ".") >= 3 {
			parts := strings.Split(subdomain, ".")
			want := strings.Join(parts[len(parts)-3:], ".")

			fmt.Println("possible good subdomain", want)
			fmt.Println("checking if it is a wildcard domain")
			fmt.Println()
			if isWildcardSubdomain(want) {
				return false
			}

			subs[want] = true
		}
		return true
	})
	for k := range subs {
		res = append(res, k)
	}
	return res
}
