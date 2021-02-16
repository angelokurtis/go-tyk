# go-tyk

A client enabling Go programs to interact with Tyk API Gateway in a simple and uniform way

[![GoDoc](https://godoc.org/github.com/angelokurtis/go-tyk?status.svg)](https://godoc.org/github.com/angelokurtis/go-tyk)
[![Go Report Card](https://goreportcard.com/badge/github.com/angelokurtis/go-tyk)](https://goreportcard.com/report/github.com/angelokurtis/go-tyk)

## Coverage

Currently, the following Tyk services are supported:

- [x] APIs
- [ ] Cache
- [ ] Health Checking
- [x] Hot Reload
- [ ] Keys
- [ ] OAuth Clients
- [ ] Quotas

## Usage

```go
import "github.com/angelokurtis/go-tyk"
```

Construct a new Tyk client, then use the various services on the client to access different parts of the Tyk API. For
example, to list all APIs:

```go
client, err := tyk.NewClient("your_token")
if err != nil {
    log.Fatalf("Failed to create client: %v", err)
}
apis, err := client.APIs.ListAPIs()
```

There are a few `With...` option functions that can be used to customize the API client. For example, to enable debug
logging:

```go
client, err := tyk.NewClient("your_token", tyk.WithDebug())
if err != nil {
    log.Fatalf("Failed to create client: %v", err)
}
status, err := client.HotReload.ReloadGroup()
```
