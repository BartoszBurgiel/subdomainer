package subdomainer

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Crawl the provided URL recursively until DepthLimit is reached and extract subdomains from the HTML.
func Crawl(path string, wg *sync.WaitGroup) {
	if Depth > DepthLimit {
		fmt.Println("depth limit reached!, aborting in", path)
		return
	}
	fmt.Println("visiting", path, "depth", Depth)

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := http.Client{
		Timeout:   time.Second * 5,
		Transport: tr,
	}
	res, err := client.Get(path)
	if err != nil {
		fmt.Println(err)
		return
	}

	html, _ := ioutil.ReadAll(res.Body)
	source := string(html)
	source = strings.ReplaceAll(source, "%2F", "")
	source = strings.ReplaceAll(source, "%3a", "")
	source = strings.ReplaceAll(source, "%3A", "")
	if source == "" {
		return
	}

	wg.Add(1)
	go analyseTLSCertificates(res.TLS, wg)
	dom := getSubdomains(source)
	for _, d := range dom {
		sub := &Subdomain{
			Domain:     strings.ToLower(d),
			Occurrence: "Crawling",
		}
		wg.Add(1)
		go Analyse(sub, wg)
	}

	links := getURLs(source)

	for _, v := range links {
		if v[0] == '/' {
			currDom := SubdomainRegex.FindString(path)

			v = "https://" + currDom + v
		}
		if _, ok := visitedURLS[v]; ok {
			continue
		}
		if v == path {
			continue
		}
		visitedURLS[v] = true
		Depth++
		Crawl(v, wg)
	}
}

func analyseTLSCertificates(t *tls.ConnectionState, wg *sync.WaitGroup) {
	defer wg.Done()
	if t == nil {
		return
	}
	domains := t.PeerCertificates[0].DNSNames
	for _, d := range domains {
		if d[0] == '*' {
			continue
		}
		sub := &Subdomain{
			Domain:     strings.ToLower(d),
			Occurrence: "TLSCert",
		}
		wg.Add(1)
		go Analyse(sub, wg)
	}
}

// sanitizeURLs removes HTML artifacts from the URLs in the provided list
func sanitizeURLs(urls []string) []string {
	urls = removeDuplicates(urls)
	for i := 0; i < len(urls); i++ {
		urls[i] = strings.ReplaceAll(urls[i], "href=", "")
		urls[i] = strings.ReplaceAll(urls[i], `"`, "")
	}
	return urls
}

// getURLs returns all relevant URLs from the HTML
func getURLs(html string) []string {
	return sanitizeURLs(LinkRegex.FindAllString(html, -1))
}

// removeDuplicates from the list
func removeDuplicates(s []string) []string {
	res := []string{}
	m := make(map[string]bool)
	for _, v := range s {
		if _, ok := m[v]; !ok {
			res = append(res, v)
			m[v] = true
		}
	}
	return res
}

// getSubdomains from the HTML
func getSubdomains(html string) []string {
	return removeDuplicates(SubdomainRegex.FindAllString(html, -1))
}

// CrawlRapidDNS and gather all new subdomains
func CrawlRapidDNS(domain string, wg *sync.WaitGroup) {
	fmt.Println("- starting rapid dns crawler...")
	wg.Add(1)
	defer wg.Done()

	for page := 1; page < 100; page++ {
		retryCount := 0
	callHandle:

		res, err := http.Get("https://rapiddns.io/s/" + domain + "?page=" + fmt.Sprintf("%d", page) + "#result")
		if err != nil {
			fmt.Println(err)
			return
		}
		if res.StatusCode == 429 {
			if retryCount > 10 {
				fmt.Println("Aborting rapiddns retries...")
				return
			}
			fmt.Println("\tTemporary limit at rapiddns reached, waiting a second")
			time.Sleep(time.Second)
			retryCount++
			goto callHandle
		}

		resp, _ := ioutil.ReadAll(res.Body)
		domains := SubdomainRegex.FindAllString(string(resp), -1)
		tempDomains := make(map[string]bool)
		for _, d := range domains {
			if d != domain {
				tempDomains[d] = true
			}
		}
		domains = []string{}
		for d := range tempDomains {
			domains = append(domains, d)
		}
		if len(domains) == 0 {
			return
		}

		for _, dom := range domains {
			sub := &Subdomain{
				Domain:     strings.ToLower(dom),
				Occurrence: "RapidDNS",
			}
			wg.Add(1)
			go Analyse(sub, wg)
		}
	}
}

// CrawlDNSDumpster and gather all subdomains and the ASN records
func CrawlDNSDumpster(domain string, wg *sync.WaitGroup) {
	fmt.Println("- crawling dns dumpser...")

	// First request to catch the CSRFToken for the query
	cl := http.Client{}
	req, _ := http.NewRequest("GET", "https://dnsdumpster.com", nil)
	req.Header.Add("user-agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36")

	resp, err := cl.Do(req)
	if err != nil {
		fmt.Println(err)
		return
	}
	setCookieHeader := resp.Header["Set-Cookie"]
	if len(setCookieHeader) == 0 {
		return
	}
	tokenHeader := setCookieHeader[0]
	token := strings.Split(tokenHeader, "=")[1]
	token = strings.Split(token, ";")[0]

	// Second request which returns the relevant results
	cl = http.Client{}
	req, err = http.NewRequest("POST", "https://dnsdumpster.com", strings.NewReader("csrfmiddlewaretoken="+token+"&targetip="+domain+"&user=free"))
	if err != nil {
		fmt.Println(err)
	}
	req.Header.Add("user-agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36")
	req.Header.Add("referer", "https://dnsdumpster.com/")
	req.Header.Add("content-type", "application/x-www-form-urlencoded")
	req.Header.Add("cookie", "csrftoken = "+token)

	resp, err = cl.Do(req)
	if err != nil {
		fmt.Println(err)
	}

	response, _ := ioutil.ReadAll(resp.Body)
	response = bytes.ReplaceAll(response, []byte("\n"), []byte{})
	rows := dnsDumpsterRowRegex.FindAllString(string(response), -1)

	for _, row := range rows {
		domain := SubdomainRegex.FindString(row)
		if domain == "" {
			continue
		}

		sub := &Subdomain{
			Domain:     strings.ToLower(domain),
			Occurrence: "DNSDumpster",
		}
		wg.Add(1)
		go Analyse(sub, wg)
	}
}

// CrawlHackertarget and extract the new subdomains
func CrawlHackertarget(domain string, wg *sync.WaitGroup) {
	fmt.Println("- starting hacktertarget crawler...")
	wg.Add(1)
	defer wg.Done()
	res, err := http.Get("https://api.hackertarget.com/hostsearch/?q=" + domain)
	if err != nil {
		fmt.Println(err)
		return
	}
	resp, _ := ioutil.ReadAll(res.Body)
	for _, dom := range strings.Split(string(resp), "\n") {
		sp := strings.Split(dom, ",")
		if len(sp) != 2 {
			continue
		}
		dom = sp[0]
		sub := &Subdomain{
			Domain:     strings.ToLower(dom),
			Occurrence: "HackerTarget",
		}
		wg.Add(1)
		go Analyse(sub, wg)
	}

}

// DeepCrawl iterares over all found domains and crawls over each subdomain using Crawl
// The function targets both http and https endpoints of the subdomain
func DeepCrawl(wg *sync.WaitGroup) {
	fmt.Println("- starting the deep crawl...")
	Subdomains.Range(func(key, value any) bool {

		fmt.Println("- deep crawl for", key.(string))
		Depth = 0
		Crawl("https://"+key.(string), wg)
		return true
	})
}

// CrawlAlienvault and extract the new subdomains as well as the ASN
func CrawlAlienvault(domain string, wg *sync.WaitGroup) {
	fmt.Println("- crawling alienvault...")
	resp, err := http.Get("https://otx.alienvault.com/api/v1/indicators/domain/" + domain + "/passive_dns")
	if err != nil {
		fmt.Println(err)
		return
	}
	bod, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println(err)
		return
	}

	res := make(map[string]interface{})
	err = json.Unmarshal(bod, &res)
	if err != nil {
		fmt.Println(err)
		return
	}

	if _, ok := res["passive_dns"]; !ok {
		return
	}

	sub := res["passive_dns"].([]interface{})
	for _, v := range sub {
		item := v.(map[string]interface{})
		if !ipRegex.MatchString(item["address"].(string)) {
			continue
		}

		dom := item["hostname"].(string)
		sub := &Subdomain{
			Occurrence: "AlienVault",
			Domain:     strings.ToLower(dom),
		}

		wg.Add(1)
		go Analyse(sub, wg)
	}
}
