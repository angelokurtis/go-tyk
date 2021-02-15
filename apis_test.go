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
		t.Errorf("APIs.ListAPIs returned %+v, want %+v", apis, want)
	}
}

func TestGetAPIByID(t *testing.T) {
	mux, server, client := setup(t)
	defer teardown(server)

	mux.HandleFunc("/tyk/apis/1", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "GET")
		fmt.Fprint(w, `{"name":"Tyk Test API","api_id":"1","org_id":"default"}`)
	})

	id := "1"
	want := &API{ID: id, Name: "Tyk Test API", OrgID: "default"}
	api, err := client.APIs.GetAPI(id)
	if err != nil {
		t.Fatalf("APIs.GetAPI returns an error: %v", err)
	}

	if !reflect.DeepEqual(want, api) {
		t.Errorf("APIs.GetAPI returned %+v, want %+v", api, want)
	}
}

func TestCreateAPI(t *testing.T) {
	mux, server, client := setup(t)
	defer teardown(server)

	mux.HandleFunc("/tyk/apis", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "POST")
	})

	err := client.APIs.CreateAPI(&CreateAPIOptions{ID: "1", Name: "Tyk Test API", OrgID: "default"})
	if err != nil {
		t.Errorf("APIs.CreateAPI returned error: %v", err)
	}
}

func TestDeleteAPI(t *testing.T) {
	mux, server, client := setup(t)
	defer teardown(server)

	mux.HandleFunc("/tyk/apis/1", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "DELETE")
	})

	err := client.APIs.DeleteAPI("1")
	if err != nil {
		t.Errorf("APIs.DeleteAPI returned error: %v", err)
	}
}
