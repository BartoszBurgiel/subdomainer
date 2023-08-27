package subdomainer

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"sync"
)

// QueryWordList iterates over a wordlist and checks if the subdomain exists
func QueryWordlist(path string, wg *sync.WaitGroup) {
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
			fmt.Println("we should be finished")
			return
		}
		sub := scanner.Text()
		scanned += int64(len(sub)) + 1
		curr := sub + "." + Domain

		if ip := dnsLookup(curr); ip != "" {
			sub := &Subdomain{}
			if _, ok := Subdomains.Load(curr); ok {
				continue
			}
			Subdomains.Store(strings.ToLower(curr), sub)
			wg.Add(1)
			go sub.Analyse(ip, curr, wg)
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
