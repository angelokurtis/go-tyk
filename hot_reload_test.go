package tyk

import (
	"fmt"
	"net/http"
	"reflect"
	"testing"
)

func TestReloadGroup(t *testing.T) {
	mux, server, client := setup(t)
	defer teardown(server)

	mux.HandleFunc("/tyk/reload/group", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "GET")
		fmt.Fprint(w, `{"status":"ok","message":""}`)
	})

	status, err := client.HotReload.ReloadGroup()
	if err != nil {
		t.Errorf("HotReload.ReloadGroup returned error: %v", err)
	}

	want := &ReloadStatus{Status: "ok", Message: ""}
	if !reflect.DeepEqual(want, status) {
		t.Errorf("HotReload.ReloadGroup returned %+v, want %+v", status, want)
	}
}
