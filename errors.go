package tyk

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"sort"
	"strings"
)

// An ResponseErr reports one or more errors caused by an API request.
type ResponseErr struct {
	Body     []byte
	Response *http.Response
	Message  string
}

func NewResponseErr(r *http.Response) *ResponseErr {
	e := &ResponseErr{Response: r}
	data, err := ioutil.ReadAll(r.Body)
	if err == nil && data != nil {
		e.Body = data
		var raw interface{}
		if err = json.Unmarshal(data, &raw); err != nil {
			e.Message = "failed to parse unknown error format"
		} else {
			e.Message = parseError(raw)
		}
	}
	return e
}

func (e *ResponseErr) Error() string {
	path, _ := url.QueryUnescape(e.Response.Request.URL.Path)
	u := fmt.Sprintf("%s://%s%s", e.Response.Request.URL.Scheme, e.Response.Request.URL.Host, path)
	return fmt.Sprintf("%s %s: %d %s", e.Response.Request.Method, u, e.Response.StatusCode, e.Message)
}

func parseError(raw interface{}) string {
	switch r := raw.(type) {
	case string:
		return r

	case []interface{}:
		var errs []string
		for _, v := range r {
			errs = append(errs, parseError(v))
		}
		return fmt.Sprintf("[%s]", strings.Join(errs, ", "))

	case map[string]interface{}:
		var errs []string
		for k, v := range r {
			errs = append(errs, fmt.Sprintf("{%s: %s}", k, parseError(v)))
		}
		sort.Strings(errs)
		return strings.Join(errs, ", ")

	default:
		return fmt.Sprintf("failed to parse unexpected error type: %T", r)
	}
}
