package subdomainer

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"sync"
)

// QueryWordList iterates over a wordlist and checks if the subdomain exists
func QueryWordlist(path, domain string, wg *sync.WaitGroup) {
	defer wg.Done()
	file, err := os.Open(path)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer file.Close()

	st, _ := os.Stat(path)
	size := st.Size()
	scanned := int64(0)

	scanner := bufio.NewScanner(file)
	cnt := 0
	for scanner.Scan() {
		if cnt > ScanLimit {
			fmt.Println("Word list query limit reached, ending the query")
			return
		}
		sub := scanner.Text()
		scanned += int64(len(sub)) + 1
		curr := sub + "." + domain

		if ip := dnsLookup(curr); ip != "" {
			sub := &Subdomain{Domain: strings.ToLower(curr), Ip: ip}
			wg.Add(1)
			go Analyse(sub, wg)
		}

		progress := float64(scanned*100) / float64(size)
		if cnt%100 == 0 {
			fmt.Printf("Progress of %s: %.2f%%.\n", path, progress)
		}
		cnt++
	}

	if err := scanner.Err(); err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println("querying", path, "is finished...")
}
