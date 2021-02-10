package tyk

import (
	"testing"
)

func TestNewClient(t *testing.T) {
	c, err := NewClient("")
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	expectedBaseURL := "http://localhost:8080/tyk/"

	if c.BaseURL().String() != expectedBaseURL {
		t.Errorf("Client's BaseURL is %s, want %s", c.BaseURL().String(), expectedBaseURL)
	}
	if c.UserAgent != "go-tyk" {
		t.Errorf("Client's UserAgent is %s, want %s", c.UserAgent, "go-tyk")
	}
}
