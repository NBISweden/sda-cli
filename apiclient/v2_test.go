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

func TestV2Client_ListFiles_Paginated(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/datasets/EGAD001/files", r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Query().Get("pageToken") {
		case "":
			fmt.Fprint(w, `{"files":[
				{"fileId":"f1","filePath":"a.c4gh","size":100,"decryptedSize":90,
				 "checksums":[{"type":"sha256","checksum":"aaaa"}],
				 "downloadUrl":"/files/f1"}
			],"nextPageToken":"ptk_b"}`)
		case "ptk_b":
			fmt.Fprint(w, `{"files":[
				{"fileId":"f2","filePath":"b.c4gh","size":200,"decryptedSize":190,
				 "checksums":[{"type":"sha256","checksum":"bbbb"}],
				 "downloadUrl":"/files/f2"}
			],"nextPageToken":null}`)
		default:
			t.Fatalf("unexpected pageToken %q", r.URL.Query().Get("pageToken"))
		}
	}))
	defer ts.Close()

	c := NewV2Client(Config{BaseURL: ts.URL, Token: "t"})
	c.http = ts.Client()

	got, err := c.ListFiles(context.Background(), "EGAD001", ListFilesOptions{})
	require.NoError(t, err)
	require.Len(t, got, 2)
	assert.Equal(t, "f1", got[0].FileID)
	assert.Equal(t, "a.c4gh", got[0].FilePath)
	assert.Equal(t, 90, got[0].DecryptedFileSize)
	assert.Equal(t, "aaaa", got[0].DecryptedFileChecksum)
	assert.Equal(t, "sha256", got[0].DecryptedFileChecksumType)
}

func TestV2Client_ListFiles_ExactFilePath(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/datasets/EGAD001/files", r.URL.Path)
		assert.Equal(t, "a.c4gh", r.URL.Query().Get("filePath"))
		assert.Empty(t, r.URL.Query().Get("pathPrefix"))
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"files":[{"fileId":"f1","filePath":"a.c4gh","size":1,"decryptedSize":1,"checksums":[],"downloadUrl":"/files/f1"}],"nextPageToken":null}`)
	}))
	defer ts.Close()

	c := NewV2Client(Config{BaseURL: ts.URL, Token: "t"})
	c.http = ts.Client()

	got, err := c.ListFiles(context.Background(), "EGAD001", ListFilesOptions{ExactPath: "a.c4gh"})
	require.NoError(t, err)
	require.Len(t, got, 1)
}

func TestV2Client_ListFiles_PathPrefix(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "dir/", r.URL.Query().Get("pathPrefix"))
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"files":[],"nextPageToken":null}`)
	}))
	defer ts.Close()

	c := NewV2Client(Config{BaseURL: ts.URL, Token: "t"})
	c.http = ts.Client()

	got, err := c.ListFiles(context.Background(), "EGAD001", ListFilesOptions{PathPrefix: "dir/"})
	require.NoError(t, err)
	assert.Empty(t, got)
}

func TestV2Client_ListFiles_BothFiltersRejectedClientSide(t *testing.T) {
	// Server would return 400; we catch earlier for better UX.
	c := NewV2Client(Config{BaseURL: "http://unused", Token: "t"})
	_, err := c.ListFiles(context.Background(), "EGAD001", ListFilesOptions{ExactPath: "a", PathPrefix: "b"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "mutually exclusive")
}
