package tyk

import (
	"github.com/angelokurtis/go-tyk/internal/log"
	"github.com/sirupsen/logrus"
)

// ClientOptionFunc can be used customize a new Tyk API client.
type ClientOptionFunc func(*Client) error

// WithBaseURL sets the base URL for API requests to a custom endpoint.
func WithBaseURL(urlStr string) ClientOptionFunc {
	return func(c *Client) error {
		return c.setBaseURL(urlStr)
	}
}

// WithDebug enables a very verbose logging
func WithDebug() ClientOptionFunc {
	return func(_ *Client) error {
		log.SetLevel(logrus.DebugLevel)
		return nil
	}
}
