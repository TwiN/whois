# whois
Lightweight library for retrieving WHOIS information on a domain.

It automatically retrieves the appropriate WHOIS server based on the domain's TLD by first querying IANA.


## Usage
```go
package main

import (
    "github.com/TwiN/whois"
)

func main() {
    client := whois.NewClient()
    output, err := client.Query("example.com")
    if err != nil {
    	panic(err)
    }
    println(output)
}
```
