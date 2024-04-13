package whois

import (
	"strings"
	"testing"
	"time"
)

func TestClient(t *testing.T) {
	scenarios := []struct {
		domain  string
		wantErr bool
	}{
		{
			domain:  "name.com",
			wantErr: false,
		},
		{
			domain:  "name.org",
			wantErr: false,
		},
		{
			domain:  "name.net",
			wantErr: false,
		},
		{
			domain:  "name.sh",
			wantErr: false,
		},
		{
			domain:  "name.io",
			wantErr: false,
		},
		{
			domain:  "name.dev",
			wantErr: false,
		},
		{
			domain:  "name.red",
			wantErr: false,
		},
		{
			domain:  "name.green",
			wantErr: false,
		},
		{
			domain:  "color.black",
			wantErr: false,
		},
		{
			domain:  "name.cn",
			wantErr: false,
		},
		{
			domain:  "name.de",
			wantErr: true,
		},
		{
			domain:  "google.com.br", // name.com.br is handled weirdly by whois.registro.br, so we'll use this instead
			wantErr: false,
		},
		{
			domain:  "name.co.ua",
			wantErr: false,
		},
		{
			domain:  "name.pp.ua",
			wantErr: false,
		},
		{
			domain:  "name.co.uk",
			wantErr: false,
		},
		{
			domain:  "name.im",
			wantErr: false,
		},
		{
			domain:  "name.uk",
			wantErr: false,
		},
		{
			domain:  "dot.scot", // name.scot not registered
			wantErr: false,
		},
		{
			domain:  "name.ru", // expiration date in `paid-till` field
			wantErr: false,
		},
		{
			domain:  "register.su", // expiration date in `paid-till` field
			wantErr: false,
		},
		{
			domain:  "nic.mx",
			wantErr: false,
		},
	}
	client := NewClient().WithReferralCache(true)
	for _, scenario := range scenarios {
		t.Run(scenario.domain+"_Query", func(t *testing.T) {
			output, err := client.Query(scenario.domain)
			if scenario.wantErr && err == nil {
				t.Error("expected error, got none")
				t.FailNow()
			}
			if !scenario.wantErr {
				if err != nil {
					t.Error("expected no error, got", err.Error())
				}
				if !strings.Contains(strings.ToLower(output), scenario.domain) {
					t.Errorf("expected %s in output, got %s", scenario.domain, output)
				}
			}
		})
		time.Sleep(50 * time.Millisecond) // Give the WHOIS servers some breathing room
		t.Run(scenario.domain+"_QueryAndParse", func(t *testing.T) {
			response, err := client.QueryAndParse(scenario.domain)
			if scenario.wantErr && err == nil {
				t.Error("expected error, got none")
				t.FailNow()
			}
			if !scenario.wantErr {
				if err != nil {
					t.Error("expected no error, got", err.Error(), "for domain", scenario.domain)
				}
				if response.ExpirationDate.Unix() <= 0 {
					t.Error("expected to have a valid expiry date, got", response.ExpirationDate.Unix(), "for domain", scenario.domain)
				}
				if len(response.NameServers) == 0 {
					t.Errorf("expected to have at least one name server for domain %s", scenario.domain)
				}
				if len(response.DomainStatuses) == 0 && !strings.HasSuffix(scenario.domain, ".im") && !strings.HasSuffix(scenario.domain, ".mx") {
					t.Errorf("expected to have at least one domain status for domain %s", scenario.domain)
				}
			}
		})
		time.Sleep(50 * time.Millisecond) // Give the WHOIS servers some breathing room
	}
}
