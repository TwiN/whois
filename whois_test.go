package whois

import (
	"strings"
	"testing"
)

func TestClient_Query(t *testing.T) {
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
	}
	for _, scenario := range scenarios {
		t.Run(scenario.domain, func(t *testing.T) {
			output, err := NewClient().Query(scenario.domain)
			if scenario.wantErr && err == nil {
				t.Error("expected error, got none")
				t.FailNow()
			}
			if !scenario.wantErr && err != nil {
				t.Error("expected no error, got", err.Error())
			}
			if !strings.Contains(strings.ToLower(output), scenario.domain) {
				t.Errorf("expected %s in output, got %s", scenario.domain, output)
			}
			t.Log(output)
		})
	}
}
