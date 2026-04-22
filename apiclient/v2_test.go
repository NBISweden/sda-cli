package apiclient

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestV2Client_ListDatasets_SinglePage(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/datasets", r.URL.Path)
		assert.Equal(t, "Bearer v2-token", r.Header.Get("Authorization"))
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"datasets":["EGAD00000000001","EGAD00000000002"],"nextPageToken":null}`)
	}))
	defer ts.Close()

	c := NewV2Client(Config{BaseURL: ts.URL, Token: "v2-token"})
	c.http = ts.Client()

	got, err := c.ListDatasets(context.Background())
	require.NoError(t, err)
	assert.Equal(t, []string{"EGAD00000000001", "EGAD00000000002"}, got)
}

func TestV2Client_ListDatasets_MultiPage(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Query().Get("pageToken") {
		case "":
			fmt.Fprint(w, `{"datasets":["EGAD001","EGAD002"],"nextPageToken":"ptk_a"}`)
		case "ptk_a":
			fmt.Fprint(w, `{"datasets":["EGAD003"],"nextPageToken":null}`)
		default:
			t.Fatalf("unexpected pageToken %q", r.URL.Query().Get("pageToken"))
		}
	}))
	defer ts.Close()

	c := NewV2Client(Config{BaseURL: ts.URL, Token: "t"})
	c.http = ts.Client()

	got, err := c.ListDatasets(context.Background())
	require.NoError(t, err)
	assert.Equal(t, []string{"EGAD001", "EGAD002", "EGAD003"}, got)
}
