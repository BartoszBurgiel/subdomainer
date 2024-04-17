package subdomainer

import "regexp"

var visitedURLS map[string]bool = make(map[string]bool, 1024)

var SubdomainRegex *regexp.Regexp
var LinkRegex *regexp.Regexp
var ipRegex *regexp.Regexp = regexp.MustCompile(`[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}`)
var dnsDumpsterRowRegex *regexp.Regexp = regexp.MustCompile(`<tr><td class="col-md-4">([a-zA-Z0-9\-\_]+\.){1,}[a-zA-Z]+<.+?</tr>`)
var dnsDumpsterANSRegex *regexp.Regexp = regexp.MustCompile(`<td class="col-md-3">([a-zA-Z0-9\_\-\ ]+)<br>`)

var Depth int
var DepthLimit int

var ScanLimit int = 1 << 20

var Domain string

var FalsePositives bool = false
