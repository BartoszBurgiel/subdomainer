package main

import (
	"flag"
	"fmt"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/BartoszBurgiel/subdomainer"
)

var wg *sync.WaitGroup = &sync.WaitGroup{}

var verbose bool

var shouldCrawl bool
var shouldDeepCrawl bool
var shouldScrape bool
var dnsGerman bool
var dnsList bool
var quickScan bool
var fullScan bool
var recurse bool
var fp bool
var customWords string

var outputJSON bool
var outputCSV bool

var shouldAquireDetails bool

var subdomainRegex *regexp.Regexp
var linkRegex *regexp.Regexp

var startTime time.Time = time.Now()

func init() {
	flag.StringVar(&subdomainer.Domain, "d", "domain.com", "the domain to scan")
	flag.IntVar(&subdomainer.DepthLimit, "n", 100, "the depth of the crawl, i.e. how many different htmls will be parsed")

	flag.BoolVar(&shouldCrawl, "crawl", false, "crawl the www.<domain> site to find subdomains")
	flag.BoolVar(&shouldDeepCrawl, "deep", false, "crawl over every found domain after all scans. depth is defined via the -n parameter")
	flag.BoolVar(&dnsGerman, "ger", false, "use a german wordlist for domains")
	flag.BoolVar(&dnsList, "list", false, "use a big dns list of domains. in most cases overkill, but you get a big coverage")
	flag.BoolVar(&quickScan, "quick", false, "quick scan looking up the top 100 most commonly used subdomains")
	flag.BoolVar(&shouldScrape, "online", false, "scrape subdomain enumeration websites such as: rapiddns, dnsdumpster and hackertarget")
	flag.BoolVar(&fullScan, "full", false, "set all of the options to true and perform the most extensive scan possible. this can take some time.")
	flag.BoolVar(&recurse, "recurse", false, "after all scans, iterate over all eligible third level domains and query them with APIs and a top 150 subdomains wordlist.")
	flag.StringVar(&customWords, "words", "", "use a custom wordlist. this can be used along other options")
	flag.BoolVar(&fp, "fp", false, "include false positives, i.e. domains found using online sources which currently have no ip assigned")

	flag.BoolVar(&outputCSV, "csv", true, "output the result to a CSV file. the path is: <domain>_report.csv")
	flag.BoolVar(&outputJSON, "json", false, "output the result to a JSON file. the path is :<domain>_report.json")

	flag.Usage = func() {
		flag.PrintDefaults()
	}

	flag.Parse()
	if fullScan {
		shouldCrawl = true
		shouldDeepCrawl = true
		dnsGerman = true
		dnsList = true
		shouldScrape = true
		recurse = true
	}

	if dnsList {
		quickScan = false
	}

	if subdomainer.DepthLimit < 0 {
		fmt.Println("the depth limit can not be negative")
		flag.PrintDefaults()
	}

	if quickScan {
		subdomainer.ScanLimit = 100
		dnsList = true
	}

	subdomainer.SubdomainRegex = regexp.MustCompile(`[a-zA-Z0-9\-\_]+(\.[a-zA-Z0-9\-\_]+)*\.` + strings.ReplaceAll(subdomainer.Domain, ".", `\.`))
	subdomainer.LinkRegex = regexp.MustCompile(`href="(http[s]?://[a-zA-Z0-9\-\_]+(\.[a-zA-Z0-9\-\_]+)*\.` + strings.ReplaceAll(subdomainer.Domain, ".", `\.`) + `)?(/[a-zA-Z0-9\-\_]+)+/([a-zA-Z0-9\-\_]+(\.htm[l]?)?)?"`)

	subdomainer.FalsePositives = fp
}

func main() {

	wg.Add(1)
	fmt.Println("=== SUBDOMAINER ===")
	fmt.Println("- analysing " + subdomainer.Domain)
	subdomainer.Analyse(&subdomainer.Subdomain{Domain: subdomainer.Domain}, wg)
	wg.Wait()
	if shouldScrape {
		subdomainer.CrawlAlienvault(subdomainer.Domain, wg)
		subdomainer.CrawlRapidDNS(subdomainer.Domain, wg)
		subdomainer.CrawlHackertarget(subdomainer.Domain, wg)
		subdomainer.CrawlDNSDumpster(subdomainer.Domain, wg)
	}

	if dnsGerman {
		fmt.Println("- querying german words...")
		wg.Add(1)
		go subdomainer.QueryWordlist("../words/german.words", subdomainer.Domain, wg)
	}

	if customWords != "" {
		fmt.Println("- querying custom words...")
		wg.Add(1)
		go subdomainer.QueryWordlist(customWords, subdomainer.Domain, wg)
	}

	if dnsList {
		fmt.Println("- querying dns words...")
		wg.Add(1)
		go subdomainer.QueryWordlist("../words/top_dns.words", subdomainer.Domain, wg)
	}

	if shouldCrawl {
		fmt.Println("- starting to crawl")
		subdomainer.Crawl("https://www."+subdomainer.Domain, wg)
	}

	fmt.Println("Waiting to finish...")
	wg.Wait()
	if shouldDeepCrawl {
		subdomainer.DeepCrawl(wg)
	}

	wg = &sync.WaitGroup{}
	if recurse {
		subdomainer.Recurse(wg)
	}
	fmt.Println("Scan finished!!!!")

	fmt.Println("Generating output...")
	outputFileDomain := strings.ReplaceAll(subdomainer.Domain, ".", "_")
	if outputCSV {
		csvFile, err := os.Create(outputFileDomain + "_result.csv")
		if err != nil {
			fmt.Println(err)
		}
		subdomainer.ExportSubdomainsToCSV(csvFile)
		csvFile.Close()
	}

	if outputJSON {
		jsonFile, err := os.Create(outputFileDomain + "_result.json")
		if err != nil {
			fmt.Println(err)
		}
		subdomainer.ExportSubdomainsToJSON(jsonFile)
		jsonFile.Close()

	}
	fmt.Println("Found domains:")
	subdomainCount := 0
	subdomainer.Subdomains.Range(func(key, value any) bool {
		fmt.Println(" -- ", key, ":", value)
		subdomainCount++
		return true
	})
	fmt.Println("Total:", subdomainCount)
	fmt.Println("The scan took", time.Since(startTime))
}
