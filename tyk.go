package tyk

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
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

	// Services used for talking to different parts of the Tyk API.
	APIs      *APIsService
	HotReload *HotReloadService
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

	c.APIs = &APIsService{client: c}
	c.HotReload = &HotReloadService{client: c}

	return c, nil
}

// setBaseURL sets the base URL for API requests to a custom endpoint.
func (c *Client) setBaseURL(urlStr string) error {
	if !strings.HasSuffix(urlStr, "/") {
		urlStr += "/"
	}

	baseURL, err := url.Parse(urlStr)
	if err != nil {
		return fmt.Errorf("failed to set the base URL: %w", err)
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

func (c *Client) GET(path string, resp interface{}) error {
	return c.makeRequest("GET", path, resp, nil)
}

func (c *Client) POST(path string, resp interface{}, payload interface{}) error {
	return c.makeRequest("POST", path, resp, payload)
}

func (c *Client) PUT(path string, resp interface{}, payload interface{}) error {
	return c.makeRequest("PUT", path, resp, payload)
}

func (c *Client) makeRequest(method, path string, resp interface{}, payload interface{}) error {
	u := *c.baseURL
	unescaped, err := url.PathUnescape(path)
	if err != nil {
		return fmt.Errorf("failed to make request: %w", err)
	}

	// Set the encoded path data
	u.RawPath = c.baseURL.Path + path
	u.Path = c.baseURL.Path + unescaped

	// Create a request specific headers map.
	headers := make(http.Header)
	headers.Set("Accept", "application/json")
	headers.Set("X-Tyk-Authorization", c.secret)

	if c.UserAgent != "" {
		headers.Set("User-Agent", c.UserAgent)
	}

	var body io.Reader
	if method == "POST" || method == "PUT" {
		headers.Set("Content-Type", "application/json")

		if payload != nil {
			b, err := json.Marshal(payload)
			if err != nil {
				return fmt.Errorf("failed to make request: %w", err)
			}
			body = bytes.NewReader(b)
		}
	}

	req, err := http.NewRequest(method, u.String(), body)
	if err != nil {
		return fmt.Errorf("failed to make request: %w", err)
	}

	// Set the request specific headers.
	for k, v := range headers {
		req.Header[k] = v
	}

	res, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("failed to make request: %w", err)
	}

	err = checkResponse(res)
	if err != nil {
		return err
	}

	if resp != nil {
		var eerr error
		if w, ok := resp.(io.Writer); ok {
			_, eerr = io.Copy(w, res.Body)
		} else {
			eerr = json.NewDecoder(res.Body).Decode(resp)
		}
		if eerr != nil {
			return fmt.Errorf("failed to decode the response: %w", eerr)
		}
	}

	return nil
}

func checkResponse(r *http.Response) error {
	switch r.StatusCode {
	case http.StatusOK, http.StatusCreated, http.StatusAccepted, http.StatusNoContent, http.StatusNotModified:
		return nil
	}

	return NewResponseErr(r)
}
