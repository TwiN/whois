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
			domain:  "example.com",
			wantErr: false,
		},
		{
			domain:  "example.org",
			wantErr: false,
		},
		{
			domain:  "twin.sh",
			wantErr: false,
		},
		{
			domain:  "gatus.io",
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
			if !strings.Contains(output, strings.ToUpper(scenario.domain)) {
				t.Errorf("expected %s in output, got %s", scenario.domain, output)
			}
		})
	}
}
