# Subdomainer
All-in-one subdomain enumeration tool. It pulls its data from some open APIs (alienvault, dnsdumpster, ... ), webscraping, brute-force enumeration as well as TLS Certificate scraping. 

## Usage 
```
  -crawl
    	crawl the www.<domain> site to find subdomains
  -csv
    	output the result to a CSV file. the path is: <domain>_report.csv (default true)
  -d string
    	the domain to scan (default "github.com")
  -deep
    	crawl over every found domain after all scans. depth is defined via the -n parameter
  -full
    	set all of the options to true and perform the most extensive scan possible. this can take some time.
  -ger
    	use a german wordlist for domains
  -json
    	output the result to a JSON file. the path is :<domain>_report.json
  -list
    	use a big dns list of domains. in most cases overkill, but you get a big coverage
  -n int
    	the depth of the crawl, i.e. how many different htmls will be parsed (default 100)
  -online
    	scrape subdomain enumeration websites such as: rapiddns, dnsdumpster and hackertarget
  -quick
    	quick scan looking up the top 100 most commonly used subdomains
  -words string
    	use a custom wordlist. this can be used along other options

```

## Tl;dr
- Quick scan of a domain: 
``go run main.go -quick -d github.com``

- Scrape www.github.com and only consider the first 500 webpages: 
``go run main.go -crawl -n 500 -d github.com``

- Try out some german words for subdomains and write the result into a json file
``go run main.go -d github.com -ger -json``

- Query the APIs and a 20k subdmain wordlist
``go run main.go -d github.com -online -list``

- Full scan. It can take some time. 
``go run main.go -d github.com -full``

