package subdomainer

import (
	"bytes"
	"crypto/sha512"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

var Subdomains *sync.Map = &sync.Map{}
var numberFuzzSubdomain *sync.Map = &sync.Map{}

type syncCounter struct {
	m   map[string]int
	mut *sync.Mutex
}

func (sc *syncCounter) newInstance(key string) {
	sc.mut.Lock()
	defer sc.mut.Unlock()
	if _, ok := sc.m[key]; ok {
		sc.m[key]++
		return
	}
	sc.m[key] = 1
}

func (sc *syncCounter) get(key string) int {
	sc.mut.Lock()
	defer sc.mut.Unlock()
	return sc.m[key]
}

var ipCounter syncCounter = syncCounter{m: make(map[string]int), mut: &sync.Mutex{}}

type Subdomain struct {
	Ip             []whoisResult `json:"ip"`
	Domain         string        `json:"domain"`
	ResponseHash   string        `json:"hash"`
	ResponseLength int           `json:"size"`
	HTMLTitle      string        `json:"title"`
	StatusCode     int           `json:"statuscode"`
	Server         string        `json:"server"`
	Occurrence     string        `json:"occurence"`
}

func Analyse(s *Subdomain, wg *sync.WaitGroup) {
	defer wg.Done()
	if !strings.HasSuffix(s.Domain, "."+Domain) {
		if s.Domain != Domain {
			return
		}
	}

	if strings.HasSuffix(s.Domain, "*.") {
		return
	}

	for _, v := range s.Ip {
		if ipCounter.get(v.Ip) > 75 {
			return
		}
	}

	if _, ok := Subdomains.Load(s.Domain); ok {
		return
	}

	if isSubdomainOfWildcardDomain(s) {
		return
	}

	if isSubdomainAltServerWildcard(s) {
		//dom := fmt.Sprintf("*.*%s*.%s",v s.Ip, s.Domain)
		//Subdomains.Store(dom, &Subdomain{Domain: dom, Ip: s.Ip})
		return
	}
	if len(s.Ip) == 0 {
		ips := dnsLookup(s.Domain)
		if len(ips) == 0 && !FalsePositives {
			return
		}
		s.Ip = ips
	}

	for _, v := range s.Ip {
		ipCounter.newInstance(v.Ip)
	}

	cl := http.Client{
		Timeout: time.Second * 2,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	r, _ := cl.Get("http://" + s.Domain)
	s.analyseResponse(r)

	if isWildcardSubdomain(s.Domain) {
		wildcard := "*." + s.Domain
		if _, ok := Subdomains.Load(wildcard); !ok {
			fmt.Println("\tgot new wildcard subdomain", dnsLookup("zimmerimmer4321."+s.Domain), "*."+s.Domain)
			Subdomains.Store("*."+s.Domain, s)
			return
		}
	}

	fmt.Println("\t- new subdomain:", s)
	Subdomains.Store(s.Domain, s)
	fuzzNumbers(s.Domain, wg)
	fuzzWWW(s.Domain, wg)
	fuzzMasks(s.Domain, wg)
}

func (s *Subdomain) analyseResponse(r *http.Response) {
	b := &bytes.Buffer{}
	if r == nil {
		s.StatusCode = -1
		s.ResponseHash = "no response"
		s.ResponseLength = -1
		s.Server = "no response"
		s.HTMLTitle = "no response"
		return
	}
	io.Copy(b, r.Body)

	s.HTMLTitle = getHTMLTitle(b.Bytes())
	s.Server = r.Header.Get("Server")

	s.ResponseLength = b.Len()
	s.StatusCode = r.StatusCode

	h := sha512.New()
	h.Write(b.Bytes())

	// just use first 12 bytes, its enough
	s.ResponseHash = string(base64.StdEncoding.EncodeToString(h.Sum(nil))[:12])
}

func getHTMLTitle(body []byte) string {
	r := regexp.MustCompile("<title>.+?</title>")
	title := r.FindString(string(body))
	if len(title) > 15 {
		return title[7 : len(title)-8]
	}
	return "no title"
}

func getCommonSubdomain(s []*Subdomain) string {
	if len(s) == 0 {
		return ""
	}
	domain := s[0].Domain
	domainParts := strings.Split(domain, ".")
	// s[1:] because we analyse the first element anywa
	for _, sub := range s[1:] {

		subParts := strings.Split(sub.Domain, ".")

		index := 0
		domainSegment := ""
		subdomainSegment := ""
		for domainSegment == subdomainSegment || index == len(subParts)-1 {
			domainSegment = domainParts[len(domainParts)-1-index]
			subdomainSegment = subParts[len(subParts)-1-index]
			index++
		}
		index--
		tempResult := strings.Join(domainParts[len(domainParts)-index:], ".")

		if len(tempResult) < len(domain) {
			domain = tempResult
		}
		if len(domainParts[len(domainParts)-index:]) == 2 {
			break
		}
	}

	return fmt.Sprintf("(%s).%s", s[0].Ip, domain)
}

func isSubdomainAltServerWildcard(s *Subdomain) bool {

	for _, v := range s.Ip {
		if ipCounter.get(v.Ip) > 25 {
			return true
		}

	}
	return false
}

func isSubdomainOfWildcardDomain(s *Subdomain) bool {
	elems := strings.Split(s.Domain, ".")

	for i := 2; i < len(elems); i++ {
		subs := "*." + strings.Join(elems[len(elems)-i:], ".")

		if wild, ok := Subdomains.Load(subs); ok {
			for _, v := range wild.(*Subdomain).Ip {
				for _, vv := range s.Ip {

					if v.Ip == vv.Ip {
						return true
					}
				}
			}
		}
	}
	return false

}

func (sub Subdomain) String() string {
	return fmt.Sprintf("%s | %s | %s | %s | %d", sub.Domain, sub.Ip, sub.HTMLTitle, sub.Server, sub.StatusCode)
}

func isWildcardSubdomain(domain string) bool {
	dummy := "z1mm3rpf74nz3."
	return len(dnsLookup(dummy+domain)) > 0
}

func fuzzWWW(domain string, wg *sync.WaitGroup) {
	if strings.HasPrefix(domain, "www.") {
		return
	}
	ip := []whoisResult{}
	if ip = dnsLookup("www." + domain); len(ip) == 0 {
		return
	}
	wg.Add(1)
	go Analyse(&Subdomain{Domain: "www." + domain, Ip: ip, Occurrence: "WWW-Fuzzing"}, wg)
}

func fuzzMasks(domain string, wg *sync.WaitGroup) {

	masks := []string{"www0.", "fw0."}

	for _, mask := range masks {
		for _, start := range masks {
			if strings.HasPrefix(domain, start) {
				return
			}
		}
		ip := []whoisResult{}
		if ip = dnsLookup(mask + domain); len(ip) == 0 {
			return
		}
		wg.Add(1)
		go Analyse(&Subdomain{Domain: mask + domain, Ip: ip, Occurrence: "Common Mask Fuzzing"}, wg)
	}
}

func fuzzNumbers(domain string, wg *sync.WaitGroup) {
	fuzzRegex := regexp.MustCompile(`\d+`)
	if _, ok := numberFuzzSubdomain.Load(fuzzRegex.ReplaceAllString(domain, "XXX")); ok {
		return
	}
	if !fuzzRegex.MatchString(domain) {
		return
	}
	mask := fuzzRegex.FindString(domain)

	if len(mask) > 3 {
		return
	}
	numberFuzzSubdomain.Store(fuzzRegex.ReplaceAllString(domain, "XXX"), true)
	fuzzedSubdomains := fuzzNumberGenerator(domain)
	fmt.Println("- beginning fuzzing of", domain)
	for _, check := range fuzzedSubdomains {

		ip := dnsLookup(check)
		if len(ip) == 0 {
			continue
		}

		if isWildcardSubdomain(check) {
			fmt.Println("Interrupting number fuzzing, wildcard is detected!", check)
			return
		}
		subd := &Subdomain{
			Occurrence: "Number fuzzing",
			Ip:         ip,
			Domain:     check,
		}
		wg.Add(1)
		go Analyse(subd, wg)
	}
}

func fuzzNumberGenerator(domain string) []string {
	domains := []string{}

	fuzzRegex := regexp.MustCompile(`\d+`)
	matches := fuzzRegex.FindAllStringSubmatch(domain, -1)

	total := 0
	for _, v := range matches {

		num := v[0]
		repeat := len(num)
		total += repeat

		if total > 3 {
			return []string{}
		}
		domain = strings.Replace(domain, num, strings.Repeat("*", repeat), 1)
	}
	if !strings.Contains(domain, "*") {
		return domains
	}
	mask := fmt.Sprintf("%%0%dd", total)
	for i := 0; i < int(math.Pow10(total)); i++ {
		num := fmt.Sprintf(mask, i)

		domains = append(domains, substitute(domain, num))
	}
	return domains
}

func substitute(mask, num string) string {
	i := 0
	t := []byte(mask)
	for num != "" {
		if mask[i] == '*' {
			t = []byte(mask)
			t[i] = byte(num[0])
			mask = string(t)
			num = num[1:]
		}
		i++
	}
	return mask
}

func ExportSubdomainsToCSV(f *os.File) {
	f.WriteString("ip,domain,title,server,status_code,response_length,response_hash\n")
	Subdomains.Range(func(key, value any) bool {
		v := value.(*Subdomain)
		domain := v.Domain
		if domain == "" {
			domain = key.(string)
		}
		fmt.Fprintf(f, "%s,%s,%s,%s,%d,%d,%s\n", v.Ip, domain, v.HTMLTitle, v.Server, v.StatusCode, v.ResponseLength, v.ResponseHash)
		return true
	})
}

// ExportSubdomainToJSON writes all of the found subdomains into a
// json map with IP adresses as keys. Example:
//
//	{
//			"1.2.3.4": [
//					{ "domain":"www.site.com", ...}
//		 ...
//	}
func ExportSubdomainsToJSON(f *os.File) {
	resultMap := []Subdomain{}

	// iterate over all domains
	Subdomains.Range(func(key, value any) bool {

		resultMap = append(resultMap, *value.(*Subdomain))

		return true
	})
	cnt, _ := json.Marshal(resultMap)
	_, err := f.Write(cnt)
	if err != nil {
		fmt.Println(err)
	}
}
