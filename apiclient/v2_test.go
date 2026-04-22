package apiclient

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestV2Client_DownloadFile_ByPath(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/datasets/EGAD001/files":
			assert.Equal(t, "a.c4gh", r.URL.Query().Get("filePath"))
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"files":[{"fileId":"f1","filePath":"a.c4gh","size":11,"decryptedSize":10,"checksums":[],"downloadUrl":"/files/f1"}],"nextPageToken":null}`)
		case "/files/f1":
			assert.Equal(t, "k-raw", r.Header.Get("X-C4GH-Public-Key"))
			w.Header().Set("Content-Length", "11")
			fmt.Fprint(w, "v2-bytes...")
		default:
			t.Fatalf("unexpected path %q", r.URL.Path)
		}
	}))
	defer ts.Close()

	c := NewV2Client(Config{BaseURL: ts.URL, Token: "t"})
	c.http = ts.Client()

	result, err := c.DownloadFile(context.Background(), DownloadRequest{
		DatasetID: "EGAD001", UserArg: "a.c4gh", PublicKeyBase64: "k-raw",
	})
	require.NoError(t, err)
	defer result.Body.Close()
	assert.Equal(t, int64(11), result.ContentLength)
}

func TestV2Client_DownloadFile_NotFound403(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/datasets/EGAD001/files", r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"files":[],"nextPageToken":null}`)
	}))
	defer ts.Close()

	c := NewV2Client(Config{BaseURL: ts.URL, Token: "t"})
	c.http = ts.Client()

	_, err := c.DownloadFile(context.Background(), DownloadRequest{
		DatasetID: "EGAD001", UserArg: "missing.c4gh", PublicKeyBase64: "k",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "dataset/file does not exist or access denied")
}

// TestV2Client_DownloadFile_ByFileID covers the bare-fileId branch of
// resolveFile: no "/" in UserArg and no ".c4gh" suffix, so the client must
// list + scan by FileID rather than use the exact-path filter.
func TestV2Client_DownloadFile_ByFileID(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/datasets/EGAD001/files":
			// No filePath filter must be set for the bare-id branch.
			assert.Empty(t, r.URL.Query().Get("filePath"))
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"files":[{"fileId":"other","filePath":"other.c4gh","downloadUrl":"/files/other"},{"fileId":"f-xyz","filePath":"a.c4gh","downloadUrl":"/files/f-xyz"}],"nextPageToken":null}`)
		case "/files/f-xyz":
			w.Header().Set("Content-Length", "3")
			fmt.Fprint(w, "xyz")
		default:
			t.Fatalf("unexpected path %q", r.URL.Path)
		}
	}))
	defer ts.Close()

	c := NewV2Client(Config{BaseURL: ts.URL, Token: "t"})
	c.http = ts.Client()

	result, err := c.DownloadFile(context.Background(), DownloadRequest{
		DatasetID: "EGAD001", UserArg: "f-xyz", PublicKeyBase64: "k",
	})
	require.NoError(t, err)
	defer result.Body.Close()
	got, _ := io.ReadAll(result.Body)
	assert.Equal(t, "xyz", string(got))
}

// TestV2Client_DownloadFile_AbsoluteDownloadURL guards URL resolution: when
// the server returns an absolute downloadUrl (e.g. a pre-signed storage
// redirect), the client must hit that URL verbatim rather than concatenate
// it onto BaseURL and produce a broken "http://apihttp://storage/..." URL.
func TestV2Client_DownloadFile_AbsoluteDownloadURL(t *testing.T) {
	storage := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", "7")
		fmt.Fprint(w, "payload")
	}))
	defer storage.Close()

	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/datasets/EGAD001/files", r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"files":[{"fileId":"f1","filePath":"a.c4gh","downloadUrl":"%s/storage/signed"}],"nextPageToken":null}`, storage.URL)
	}))
	defer api.Close()

	c := NewV2Client(Config{BaseURL: api.URL, Token: "t"})
	c.http = api.Client()

	result, err := c.DownloadFile(context.Background(), DownloadRequest{
		DatasetID: "EGAD001", UserArg: "a.c4gh", PublicKeyBase64: "k",
	})
	require.NoError(t, err)
	defer result.Body.Close()
	got, _ := io.ReadAll(result.Body)
	assert.Equal(t, "payload", string(got))
}

// TestV2Client_DownloadFile_ListForbidden403 guards the existence-leakage
// contract for the list-resolution step: a 403 from GET /datasets/{id}/files
// must be flattened to the same ambiguous message as a 200-with-empty-list
// so that a forbidden dataset is indistinguishable from a missing one.
func TestV2Client_DownloadFile_ListForbidden403(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/datasets/EGAD001/files", r.URL.Path)
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, `{"title":"Forbidden","status":403,"detail":"access denied"}`)
	}))
	defer ts.Close()

	c := NewV2Client(Config{BaseURL: ts.URL, Token: "t"})
	c.http = ts.Client()

	_, err := c.DownloadFile(context.Background(), DownloadRequest{
		DatasetID: "EGAD001", UserArg: "a.c4gh", PublicKeyBase64: "k",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "dataset/file does not exist or access denied")
	assert.NotContains(t, err.Error(), "403", "403 status must not leak through")
}

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

func TestV2Client_DatasetInfo(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/datasets/EGAD001", r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"datasetId":"EGAD001","files":42,"size":1234567890}`)
	}))
	defer ts.Close()

	c := NewV2Client(Config{BaseURL: ts.URL, Token: "t"})
	c.http = ts.Client()

	got, err := c.DatasetInfo(context.Background(), "EGAD001")
	require.NoError(t, err)
	assert.Equal(t, "EGAD001", got.DatasetID)
	assert.Equal(t, 42, got.FileCount)
	assert.Equal(t, int64(1234567890), got.Size)
}
