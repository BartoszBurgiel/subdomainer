package subdomainer

import (
	"fmt"
	"testing"
)

func TestNumberFuzzing(t *testing.T) {
	dom := "c-n2k-v30.rz.eduport.hamburg.de"

	fmt.Println(fuzzNumberGenerator(dom))
	fmt.Println(fuzzNumberGenerator("cv-v23-t-2-mx1.domain.com"))

}
