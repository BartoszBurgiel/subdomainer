# Subdomainer
All-in-one subdomain enumeration tool. It uses open APIs (alienvault, dnsdumpster, ... ), webscraping, brute-force enumeration as well as TLS Certificate scraping. Use only on sites with permissions. 

## Wordlists
The project contains wordlists for scanning already. Currently there are two wordlists: 
- list of all german words (for edge cases like: `bestellung.webseite.de`)
- list of top 20.000 subdomains

You can of course use your own wordlists with the `-words` parameter like so: 

`go run main.go -d domain.com -w my_wordlist.words`

## Fuzzing
The subdomainer is capable of detecting certain patterns in the subdomains and enumerate this. Having found a subdomain like this: `fw0.website.de`, will trigger the Subdomainer to iterate over all single-digit numbers, i.e. `fw0.website.de`, `fw1.website.de`, ... , `fw9.website.de`. This mechanism is limited to 1.000 iterations per masc, i.e. having a subdomain like: `fw000001.website.de` won't cause the subdomainer to iterate over all possibilities.

## Recursion 
The subdomainer can be set to recurse over all found domains. This means, that the same mechanism which was used to enumerate the root will be applied to all of its subdomains. 

## Wildcard detection 
Subdomainer detects wildcard subdomains by counting the observed IPs. If domains are is resolved to the same IP address more than 75 times, the deepest common subdomain is declared as a wildcard domain. 

Example: 

```
www.website.de -> 1.2.3.4
test.website.de -> 1.2.3.4
store.website.de -> 1.2.3.4
...
gw.website.de -> 1.2.3.4
```
The above scenario will result in the subdomainer to determining that `*.website.de` is a wildcard domain. 


## Usage 
```
  -crawl
        crawl the www.<domain> site to find subdomains
  -csv
        output the result to a CSV file. the path is: <domain>_report.csv (default true)
  -d string
        the domain to scan (default "domain.com")
  -deep
        crawl over every found domain after all scans. depth is defined via the -n parameter
  -fp
        include false positives, i.e. domains found using online sources which currently have no ip assigned
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
  -recurse
        after all scans, iterate over all eligible third level domains and query them with APIs and a top 150 subdomains wordlist.
  -words string
        use a custom wordlist. this can be used along other options

```

### Tl;dr
- Quick scan of a domain: 

``go run main.go -quick -d github.com``

- Scrape www.github.com and only consider the first 500 webpages: 

``go run main.go -crawl -n 500 -d github.com``

- Try out some german words for subdomains and write the result into a json file:

``go run main.go -d github.com -ger -json``

- Query the APIs and a apply a 20k subdmain wordlist:

``go run main.go -d github.com -online -list``

- Full scan. It can take some time:

``go run main.go -d github.com -full``

