package tyk

// ClientOptionFunc can be used customize a new Tyk API client.
type ClientOptionFunc func(*Client) error
