package oidc

import (
	"strings"
	"testing"

	"golang.org/x/oauth2"

	"github.com/coreos/dex/connector"
)

func TestKnownBrokenAuthHeaderProvider(t *testing.T) {
	tests := []struct {
		issuerURL string
		expect    bool
	}{
		{"https://dev.oktapreview.com", true},
		{"https://dev.okta.com", true},
		{"https://okta.com", true},
		{"https://dev.oktaaccounts.com", false},
		{"https://accounts.google.com", false},
	}

	for _, tc := range tests {
		got := knownBrokenAuthHeaderProvider(tc.issuerURL)
		if got != tc.expect {
			t.Errorf("knownBrokenAuthHeaderProvider(%q), want=%t, got=%t", tc.issuerURL, tc.expect, got)
		}
	}
}

func TestLoginURL_PromptParameter(t *testing.T) {
	callbackURL := "https://example.com/callback"

	tests := []struct {
		name          string
		prompt        string
		hostedDomains []string
		wantPrompt    bool
		wantHD        bool
	}{
		{
			name:       "includes prompt parameter when configured",
			prompt:     "select_account",
			wantPrompt: true,
		},
		{
			name:       "omits prompt parameter when not configured",
			prompt:     "",
			wantPrompt: false,
		},
		{
			name:          "includes both prompt and hd parameters",
			prompt:        "select_account",
			hostedDomains: []string{"example.com"},
			wantPrompt:    true,
			wantHD:        true,
		},
		{
			name:          "includes hd without prompt when prompt not configured",
			prompt:        "",
			hostedDomains: []string{"example.com"},
			wantPrompt:    false,
			wantHD:        true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			conn := &oidcConnector{
				redirectURI: callbackURL,
				oauth2Config: &oauth2.Config{
					ClientID: "test-client-id",
					Endpoint: oauth2.Endpoint{
						AuthURL: "https://accounts.google.com/o/oauth2/v2/auth",
					},
					RedirectURL: callbackURL,
				},
				prompt:        tc.prompt,
				hostedDomains: tc.hostedDomains,
			}

			loginURL, err := conn.LoginURL(connector.Scopes{}, callbackURL, "test-state")
			if err != nil {
				t.Fatalf("LoginURL() error: %v", err)
			}

			hasPrompt := strings.Contains(loginURL, "prompt=select_account")
			if hasPrompt != tc.wantPrompt {
				t.Errorf("LoginURL() prompt in URL = %v, want %v. URL: %s", hasPrompt, tc.wantPrompt, loginURL)
			}

			hasHD := strings.Contains(loginURL, "hd=")
			if hasHD != tc.wantHD {
				t.Errorf("LoginURL() hd in URL = %v, want %v. URL: %s", hasHD, tc.wantHD, loginURL)
			}
		})
	}
}
