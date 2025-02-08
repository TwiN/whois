package whois

import (
	"errors"
	"io"
	"net"
	"strings"
	"time"
)

const (
	ianaWHOISServerAddress = "whois.iana.org:43"
)

var tldWithoutExpirationDate = []string{"at", "be", "ch", "co.at", "com.br", "or.at", "de", "fr", "nl"}

type Client struct {
	whoisServerAddress string

	isCachingReferralWHOISServers bool
	referralWHOISServersCache     map[string]string
}

func NewClient() *Client {
	return &Client{
		whoisServerAddress:        ianaWHOISServerAddress,
		referralWHOISServersCache: make(map[string]string),
	}
}

// WithReferralCache allows you to enable or disable the referral WHOIS server cache.
// While ianaWHOISServerAddress is the "entry point" for WHOIS queries, it sometimes has
// availability issues. One way to mitigate this is to cache the referral WHOIS server.
//
// This is disabled by default
func (c *Client) WithReferralCache(enabled bool) *Client {
	c.isCachingReferralWHOISServers = enabled
	if enabled {
		// We'll set a couple of common ones right away to avoid unnecessary queries
		c.referralWHOISServersCache = map[string]string{
			"com":   "whois.verisign-grs.com",
			"black": "whois.nic.black",
			"dev":   "whois.nic.google",
			"green": "whois.nic.green",
			"io":    "whois.nic.io",
			"net":   "whois.verisign-grs.com",
			"org":   "whois.publicinterestregistry.org",
			"red":   "whois.nic.red",
			"sh":    "whois.nic.sh",
			"uk":    "whois.nic.uk",
			"mx":    "whois.nic.mx",
		}
	}
	return c
}

func doesTLDHaveExpirationDate(e string) bool {
	for _, a := range tldWithoutExpirationDate {
		if a == e {
			return true
		}
	}
	return false
}

func (c *Client) Query(domain string) (string, error) {
	parts := strings.Split(domain, ".")
	domainExtension := parts[len(parts)-1]
	if doesTLDHaveExpirationDate(domainExtension) {
		return "", errors.New("domain extension " + domainExtension + " does not have a grace period.")
	}
	if c.isCachingReferralWHOISServers {
		if cachedWHOISServer, ok := c.referralWHOISServersCache[domain]; ok {
			return c.query(cachedWHOISServer, domain)
		}
	}
	var output string
	var err error
	switch domainExtension {
	case "ua":
		if len(parts) > 2 && len(parts[len(parts)-2]) < 4 {
			domainExtension = parts[len(parts)-2] + "." + domainExtension
		}
		output, err = c.query("whois."+domainExtension+":43", domain)
	default:
		output, err = c.query(c.whoisServerAddress, domainExtension)
	}
	if err != nil {
		return "", err
	}
	if strings.Contains(output, "whois:") {
		startIndex := strings.Index(output, "whois:") + 6
		endIndex := strings.Index(output[startIndex:], "\n") + startIndex
		whois := strings.TrimSpace(output[startIndex:endIndex])
		if referOutput, err := c.query(whois+":43", domain); err == nil {
			if c.isCachingReferralWHOISServers {
				c.referralWHOISServersCache[domain] = whois + ":43"
			}
			return referOutput, nil
		}
		return "", err
	}
	return output, nil
}

func (c *Client) query(whoisServerAddress, domain string) (string, error) {
	connection, err := net.DialTimeout("tcp", whoisServerAddress, 10*time.Second)
	if err != nil {
		return "", err
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(5 * time.Second))
	_, err = connection.Write([]byte(domain + "\r\n"))
	if err != nil {
		return "", err
	}
	output, err := io.ReadAll(connection)
	if err != nil {
		return "", err
	}
	return string(output), nil
}

type Response struct {
	ExpirationDate time.Time
	DomainStatuses []string
	NameServers    []string
}

// QueryAndParse tries to parse the response from the WHOIS server
// There is no standardized format for WHOIS responses, so this is an attempt at best.
//
// Being the selfish person that I am, I also only parse the fields that I need.
// If you need more fields, please open an issue or pull request.
func (c *Client) QueryAndParse(domain string) (*Response, error) {
	text, err := c.Query(domain)
	if err != nil {
		return nil, err
	}
	response := Response{}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		valueStartIndex := strings.Index(line, ":")
		if valueStartIndex == -1 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(line[:valueStartIndex]))
		value := strings.TrimSpace(line[valueStartIndex+1:])
		if strings.Contains(key, "expir") {
			switch {
			case strings.HasSuffix(domain, ".pp.ua"):
				response.ExpirationDate, _ = time.Parse("02-Jan-2006 15:04:05 MST", strings.ToUpper(value))
			case strings.HasSuffix(domain, ".ua"):
				response.ExpirationDate, _ = time.Parse("2006-01-02 15:04:05Z07", strings.ToUpper(value))
			case strings.HasSuffix(domain, ".uk"):
				response.ExpirationDate, _ = time.Parse("02-Jan-2006", strings.ToUpper(value))
			case strings.HasSuffix(domain, ".cz"):
				response.ExpirationDate, _ = time.Parse("02.01.2006", strings.ToUpper(value))
			// case strings.HasSuffix(domain, ".me"):
			// 	response.ExpirationDate, _ = time.Parse("2006-01-02T15:04:05Z", strings.ToUpper(value))
			case strings.HasSuffix(domain, ".im"):
				response.ExpirationDate, _ = time.Parse("02/01/2006 15:04:05", strings.ToUpper(value))
			case strings.HasSuffix(domain, ".scot"):
				if !strings.Contains(key, "registrar") {
					response.ExpirationDate, _ = time.Parse(time.RFC3339, strings.ToUpper(value))
				}
			case strings.HasSuffix(domain, ".br"):
				response.ExpirationDate, _ = time.Parse("20060102", strings.ToUpper(value))
			case strings.HasSuffix(domain, ".cn"):
				response.ExpirationDate, _ = time.Parse("2006-01-02 15:04:05", strings.ToUpper(value))
			case strings.HasSuffix(domain, ".mx"):
				response.ExpirationDate, _ = time.Parse(time.DateOnly, strings.ToUpper(value))
			default:
				response.ExpirationDate, _ = time.Parse(time.RFC3339, strings.ToUpper(value))
			}
		} else if key == "paid-till" {
			// example for ru/su domains -> paid-till: 2024-05-26T21:00:00Z
			if strings.HasSuffix(domain, ".ru") || strings.HasSuffix(domain, ".su") {
				response.ExpirationDate, _ = time.Parse(time.RFC3339, strings.ToUpper(value))
			}
		} else if strings.Contains(key, "status") {
			response.DomainStatuses = append(response.DomainStatuses, value)
		} else if key == "state" {
			// example for ru/su domains -> state: DELEGATED, VERIFIED
			if strings.HasSuffix(domain, ".ru") || strings.HasSuffix(domain, ".su") {
				response.DomainStatuses = strings.Split(value, ", ")
			}
		} else if strings.Contains(key, "name server") || strings.Contains(key, "nserver") {
			response.NameServers = append(response.NameServers, value)
		}
	}
	return &response, nil
}