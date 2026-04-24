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

func TestV1Client_ListDatasets(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/metadata/datasets", r.URL.Path)
		assert.Equal(t, "Bearer test-token", r.Header.Get("Authorization"))
		assert.Equal(t, "test", r.Header.Get("SDA-Client-Version"))
		fmt.Fprint(w, `["https://doi.example/ds1","https://doi.example/ds2"]`)
	}))
	defer ts.Close()

	c := NewV1Client(Config{BaseURL: ts.URL, Token: "test-token", Version: "test"}, nil)
	c.http = ts.Client() // inject to bypass ensureJar

	got, err := c.ListDatasets(context.Background())
	require.NoError(t, err)
	assert.Equal(t, []string{"https://doi.example/ds1", "https://doi.example/ds2"}, got)
}

func TestV1Client_ListDatasets_ServerError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, "forbidden")
	}))
	defer ts.Close()

	c := NewV1Client(Config{BaseURL: ts.URL, Token: "t"}, nil)
	c.http = ts.Client()

	_, err := c.ListDatasets(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "status 403")
}

func TestV1Client_ListDatasets_PreconditionFailed(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusPreconditionFailed)
		fmt.Fprint(w, "  dataset consent expired  ")
	}))
	defer ts.Close()

	c := NewV1Client(Config{BaseURL: ts.URL, Token: "t"}, nil)
	c.http = ts.Client()

	_, err := c.ListDatasets(context.Background())
	require.Error(t, err)
	assert.Equal(t, "dataset consent expired", err.Error())
}

func TestV1Client_ListDatasets_InvalidJSON(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, "not json")
	}))
	defer ts.Close()

	c := NewV1Client(Config{BaseURL: ts.URL, Token: "t"}, nil)
	c.http = ts.Client()

	_, err := c.ListDatasets(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse dataset list")
}

func TestV1Client_ListFiles(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/metadata/datasets/TES01/files", r.URL.Path)
		assert.Equal(t, "Bearer t", r.Header.Get("Authorization"))
		assert.Empty(t, r.Header.Get("Client-Public-Key"), "no pubkey → no header")
		fmt.Fprint(w, `[
			{"fileId":"f1","displayFileName":"a.c4gh","filePath":"dir/a.c4gh","decryptedFileSize":100},
			{"fileId":"f2","displayFileName":"b.c4gh","filePath":"dir/b.c4gh","decryptedFileSize":200}
		]`)
	}))
	defer ts.Close()

	c := NewV1Client(Config{BaseURL: ts.URL, Token: "t"}, nil)
	c.http = ts.Client()

	got, err := c.ListFiles(context.Background(), "TES01", ListFilesOptions{})
	require.NoError(t, err)
	require.Len(t, got, 2)
	assert.Equal(t, "f1", got[0].FileID)
	assert.Equal(t, "dir/a.c4gh", got[0].FilePath)
	assert.Equal(t, 100, got[0].DecryptedFileSize)
}

// Guards the §5 "zero user-visible behavior change" guarantee: pre-abstraction the
// fileCase → getFileIDURL → GetFilesInfo → getBody chain forwarded the
// caller's pubkey as Client-Public-Key on /files listing requests.
// LegacyV1PubKey preserves that wire behavior through V1Client.
func TestV1Client_ListFiles_ForwardsLegacyV1PubKey(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "pubkey-b64", r.Header.Get("Client-Public-Key"))
		fmt.Fprint(w, `[]`)
	}))
	defer ts.Close()

	c := NewV1Client(Config{BaseURL: ts.URL, Token: "t"}, nil)
	c.http = ts.Client()

	_, err := c.ListFiles(context.Background(), "TES01", ListFilesOptions{
		LegacyV1PubKey: "pubkey-b64",
	})
	require.NoError(t, err)
}

// Guards the "failed to parse file list" prefix that download.GetFilesInfo
// relies on to skip double-wrapping parse errors. See download.GetFilesInfo.
func TestV1Client_ListFiles_InvalidJSON(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, "not json")
	}))
	defer ts.Close()

	c := NewV1Client(Config{BaseURL: ts.URL, Token: "t"}, nil)
	c.http = ts.Client()

	_, err := c.ListFiles(context.Background(), "TES01", ListFilesOptions{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse file list")
}

func TestV1Client_ListFiles_RejectsV2Options(t *testing.T) {
	c := NewV1Client(Config{BaseURL: "http://unused", Token: "t"}, nil)

	_, err := c.ListFiles(context.Background(), "TES01", ListFilesOptions{ExactPath: "a"})
	require.ErrorIs(t, err, ErrNotSupportedOnV1)

	_, err = c.ListFiles(context.Background(), "TES01", ListFilesOptions{PathPrefix: "dir/"})
	require.ErrorIs(t, err, ErrNotSupportedOnV1)
}

func TestV1Client_DatasetInfo_NotSupported(t *testing.T) {
	c := NewV1Client(Config{BaseURL: "http://unused", Token: "t"}, nil)
	_, err := c.DatasetInfo(context.Background(), "TES01")
	require.ErrorIs(t, err, ErrNotSupportedOnV1)
}

func TestV1Client_DownloadFile_ByPath(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/metadata/datasets/TES01/files":
			fmt.Fprint(w, `[{"fileId":"f1","displayFileName":"a.c4gh","filePath":"dir/a.c4gh"}]`)
		case "/s3/TES01/dir/a.c4gh":
			assert.Equal(t, "key-b64", r.Header.Get("Client-Public-Key"))
			w.Header().Set("Content-Length", "11")
			fmt.Fprint(w, "encrypted..")
		default:
			t.Fatalf("unexpected path %q", r.URL.Path)
		}
	}))
	defer ts.Close()

	c := NewV1Client(Config{BaseURL: ts.URL, Token: "t"}, nil)
	c.SetHTTPClientForTest(ts.Client())

	result, err := c.DownloadFile(context.Background(), DownloadRequest{
		DatasetID:       "TES01",
		UserArg:         "dir/a.c4gh",
		PublicKeyBase64: "key-b64",
	})
	require.NoError(t, err)
	defer result.Body.Close()
	assert.Equal(t, int64(11), result.ContentLength)
	b, _ := io.ReadAll(result.Body)
	assert.Equal(t, "encrypted..", string(b))
}

func TestV1Client_DownloadFile_ByID(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/metadata/datasets/TES01/files":
			fmt.Fprint(w, `[{"fileId":"f-xyz","displayFileName":"a.c4gh","filePath":"a.c4gh"}]`)
		case "/s3/TES01/a.c4gh":
			w.Header().Set("Content-Length", "5")
			fmt.Fprint(w, "hello")
		default:
			t.Fatalf("unexpected path %q", r.URL.Path)
		}
	}))
	defer ts.Close()

	c := NewV1Client(Config{BaseURL: ts.URL, Token: "t"}, nil)
	c.SetHTTPClientForTest(ts.Client())

	result, err := c.DownloadFile(context.Background(), DownloadRequest{
		DatasetID: "TES01", UserArg: "f-xyz", PublicKeyBase64: "key",
	})
	require.NoError(t, err)
	defer result.Body.Close()
}

// TestV1Client_DownloadFile_StripsUserPrefix guards the v1 /s3 URL against
// a user-prefixed FilePath: the retired download.getFileIDURL ran
// AnonymizeFilepath before URL construction, and the v1 server expects the
// prefix already stripped. Regression here would 404 every v1 download for
// users whose dataset files carry a "user_<email>/..." prefix.
func TestV1Client_DownloadFile_StripsUserPrefix(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/metadata/datasets/TES01/files":
			fmt.Fprint(w, `[{"fileId":"f1","displayFileName":"a.c4gh","filePath":"user_example.com/files/a.c4gh"}]`)
		case "/s3/TES01/files/a.c4gh":
			fmt.Fprint(w, "ok")
		default:
			t.Fatalf("unexpected path %q — user prefix should have been stripped", r.URL.Path)
		}
	}))
	defer ts.Close()

	c := NewV1Client(Config{BaseURL: ts.URL, Token: "t"}, nil)
	c.SetHTTPClientForTest(ts.Client())

	result, err := c.DownloadFile(context.Background(), DownloadRequest{
		DatasetID: "TES01", UserArg: "files/a.c4gh",
	})
	require.NoError(t, err)
	defer result.Body.Close()
}

// TestV1Client_DownloadFile_WrapsListFailure guards the legacy
// "failed to get files, reason: ..." error prefix on list-resolution
// failures inside DownloadFile. Scripts and the download.go shim have
// asserted on this prefix since before the apiclient abstraction; without
// the wrap, callers see the bare transport error and string-matching
// breaks.
func TestV1Client_DownloadFile_WrapsListFailure(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, "boom")
	}))
	defer ts.Close()

	c := NewV1Client(Config{BaseURL: ts.URL, Token: "t"}, nil)
	c.SetHTTPClientForTest(ts.Client())

	_, err := c.DownloadFile(context.Background(), DownloadRequest{
		DatasetID: "TES01", UserArg: "anything", PublicKeyBase64: "k",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get files, reason:")
}
