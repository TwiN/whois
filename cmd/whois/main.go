package main

import (
	"fmt"
	"os"

	"github.com/TwiN/whois"
)

func main() {
	if len(os.Args) != 2 {
		_, _ = fmt.Fprintln(os.Stderr, "you must provide exactly one domain")
		os.Exit(1)
		return
	}
	output, err := whois.NewClient().Query(os.Args[1])
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
	fmt.Println(output)
}
