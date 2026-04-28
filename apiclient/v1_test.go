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
