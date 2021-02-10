package tyk

import (
	"net/http"
	"net/url"
	"strings"
)

const (
	defaultBaseURL = "http://localhost:8080/"
	apiVersionPath = "tyk/"
	userAgent      = "go-tyk"
)

// A Client manages communication with the Tyk API Gateway.
type Client struct {
	// Internal HTTP client.
	http *http.Client
	// Base URL for API requests.
	baseURL *url.URL
	// The Tyk Gateway API secret that was stored in your tyk.conf.
	secret string
	// User agent used when communicating with the Tyk API.
	UserAgent string
}

// NewClient returns a new Tyk API client. To use API methods which require authentication,
// provide the secret that was stored in your tyk.conf.
func NewClient(secret string, options ...ClientOptionFunc) (*Client, error) {
	c, err := newClient(options...)
	if err != nil {
		return nil, err
	}
	c.secret = secret
	return c, nil
}

func newClient(options ...ClientOptionFunc) (*Client, error) {
	c := &Client{http: http.DefaultClient, UserAgent: userAgent}

	err := c.setBaseURL(defaultBaseURL)
	if err != nil {
		return nil, err
	}

	err = c.apply(options...)
	if err != nil {
		return nil, err
	}

	return c, nil
}

// setBaseURL sets the base URL for API requests to a custom endpoint.
func (c *Client) setBaseURL(urlStr string) error {
	if !strings.HasSuffix(urlStr, "/") {
		urlStr += "/"
	}

	baseURL, err := url.Parse(urlStr)
	if err != nil {
		return err
	}

	if !strings.HasSuffix(baseURL.Path, apiVersionPath) {
		baseURL.Path += apiVersionPath
	}

	c.baseURL = baseURL

	return nil
}

// Apply any given client options.
func (c *Client) apply(options ...ClientOptionFunc) error {
	for _, fn := range options {
		if fn == nil {
			continue
		}
		if err := fn(c); err != nil {
			return err
		}
	}
	return nil
}

// BaseURL return a copy of the baseURL.
func (c *Client) BaseURL() *url.URL {
	u := *c.baseURL
	return &u
}
