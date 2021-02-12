package tyk

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// setup sets up a test HTTP server along with a tyk.Client that is
// configured to talk to that test server.  Tests should register handlers on
// mux which provide mock responses for the API method being tested.
func setup(t *testing.T) (*http.ServeMux, *httptest.Server, *Client) {
	// mux is the HTTP request multiplexer used with the test server.
	mux := http.NewServeMux()

	// server is a test HTTP server used to provide mock API responses.
	server := httptest.NewServer(mux)

	// client is the Tyk client being tested.
	client, err := NewClient("", WithBaseURL(server.URL))
	if err != nil {
		server.Close()
		t.Fatalf("failed to create client: %v", err)
	}

	return mux, server, client
}

// teardown closes the test HTTP server.
func teardown(server *httptest.Server) {
	server.Close()
}

func testMethod(t *testing.T, r *http.Request, want string) {
	if got := r.Method; got != want {
		t.Errorf("Request method: %s, want %s", got, want)
	}
}

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
