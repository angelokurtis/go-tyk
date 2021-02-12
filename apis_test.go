package tyk

import (
	"fmt"
	"net/http"
	"reflect"
	"testing"
)

func TestListAPIs(t *testing.T) {
	mux, server, client := setup(t)
	defer teardown(server)

	mux.HandleFunc("/tyk/apis", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "GET")
		fmt.Fprint(w, `[{"api_id":"1"},{"api_id":"2"}]`)
	})

	apis, err := client.APIs.ListAPIs()
	if err != nil {
		t.Errorf("APIs.ListAPIs returned error: %v", err)
	}

	want := []*API{{ID: "1"}, {ID: "2"}}
	if !reflect.DeepEqual(want, apis) {
		t.Errorf("Projects.ListProjects returned %+v, want %+v", apis, want)
	}
}
