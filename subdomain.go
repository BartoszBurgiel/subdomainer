package subdomainer

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

type Subdomain struct {
	Ip     string `json:"ip"`
	Domain string `json:"domain"`
	Http   bool   `json:"http"`
	Https  bool   `json:"https"`
	ASN    string `json:"asn"`
}

func (sub *Subdomain) Analyse(ip, domain string, wg *sync.WaitGroup) {
	defer wg.Done()
	fmt.Println("\tgot new subdomain", ip, domain)
	if ip == "" {
		sub.Ip = "offline"
		return
	}
	if !strings.HasSuffix(domain, Domain) {
		return
	}
	sub.Ip = ip
	sub.Domain = domain
	cl := http.Client{
		Timeout: time.Second * 2,
	}
	_, http_err := cl.Get("http://" + domain)
	_, https_err := cl.Get("https://" + domain)
	sub.Http = http_err == nil
	sub.Https = https_err == nil

	if sub.ASN == "" {
		sub.ASN = "unknown"

	}
}

func (sub Subdomain) String() string {
	return fmt.Sprintf("%s %s %v/%v %s", sub.Ip, sub.Domain, sub.Http, sub.Https, sub.ASN)
}

var Subdomains sync.Map = sync.Map{}

func ExportSubdomainsToCSV(f *os.File) {
	f.WriteString("ip,domain,http,https,asn\n")
	Subdomains.Range(func(key, value any) bool {
		v := value.(*Subdomain)
		fmt.Fprintf(f, "%s,%s,%v,%v,%s\n", v.Ip, v.Domain, v.Http, v.Https, v.ASN)
		return true
	})
}

func ExportSubdomainsToJSON(f *os.File) {
	f.WriteString("[")
	fmt.Println("these are all of the domains:")
	res := []string{}
	Subdomains.Range(func(key, value any) bool {
		jsn, _ := json.Marshal(value)
		res = append(res, string(jsn))
		return true
	})
	f.WriteString(strings.Join(res, ","))
	f.WriteString("]")
}
