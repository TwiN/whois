package whois

import (
	"io"
	"net"
	"strings"
	"time"
)

const (
	ianaWHOISServerAddress = "whois.iana.org:43"
)

type Client struct {
	whoisServerAddress string
}

func NewClient() *Client {
	return &Client{
		whoisServerAddress: ianaWHOISServerAddress,
	}
}

func (c Client) Query(domain string) (string, error) {
	parts := strings.Split(domain, ".")
	output, err := c.query(c.whoisServerAddress, parts[len(parts)-1])
	if err != nil {
		return "", err
	}
	if strings.Contains(output, "whois:") {
		startIndex := strings.Index(output, "whois:") + 6
		endIndex := strings.Index(output[startIndex:], "\n") + startIndex
		whois := strings.TrimSpace(output[startIndex:endIndex])
		if referOutput, err := c.query(whois+":43", domain); err == nil {
			return referOutput, nil
		}
		return "", err
	}
	return output, nil
}

func (c Client) query(whoisServerAddress, domain string) (string, error) {
	connection, err := net.DialTimeout("tcp", whoisServerAddress, 10*time.Second)
	if err != nil {
		return "", err
	}
	defer connection.Close()
	connection.SetDeadline(time.Now().Add(5 * time.Second))
	_, err = connection.Write([]byte(domain + "\n"))
	if err != nil {
		return "", err
	}
	output, err := io.ReadAll(connection)
	if err != nil {
		return "", err
	}
	return string(output), nil
}
