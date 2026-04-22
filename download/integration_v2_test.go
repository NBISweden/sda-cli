//go:build integration

package download_test

import (
	"context"
	"io"
	"os"
	"testing"

	"github.com/NBISweden/sda-cli/apiclient"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// buildIntegrationClient constructs a v2 apiclient.Client pointed at the
// dev stack. Requires:
//   - dev-tools/download-v2-dev/ stack is up (make dev-download-v2-up)
//   - DOWNLOAD_V2_URL env var (default http://localhost:8085)
//   - DOWNLOAD_V2_TOKEN env var (dev token from mockauth)
func buildIntegrationClient(t *testing.T) apiclient.Client {
	t.Helper()
	baseURL := os.Getenv("DOWNLOAD_V2_URL")
	if baseURL == "" {
		baseURL = "http://localhost:8085"
	}
	token := os.Getenv("DOWNLOAD_V2_TOKEN")
	require.NotEmpty(t, token, "DOWNLOAD_V2_TOKEN must be set (curl /tokens on mockauth)")

	client, err := apiclient.New(apiclient.Config{
		BaseURL: baseURL,
		Token:   token,
		Version: "test",
	}, "v2")
	require.NoError(t, err)
	return client
}

// TestV2_ListDatasets_Smoke calls the real v2 dev stack.
func TestV2_ListDatasets_Smoke(t *testing.T) {
	client := buildIntegrationClient(t)

	got, err := client.ListDatasets(context.Background())
	require.NoError(t, err)
	assert.Contains(t, got, "EGAD00000000001", "dev stack should expose seeded dataset EGAD00000000001")
}

func TestV2_ListFiles_Smoke(t *testing.T) {
	client := buildIntegrationClient(t)
	files, err := client.ListFiles(context.Background(), "EGAD00000000001", apiclient.ListFilesOptions{})
	require.NoError(t, err)
	assert.NotEmpty(t, files, "seeded dataset should have at least one file")
}

func TestV2_ListFiles_ExactPath_Smoke(t *testing.T) {
	client := buildIntegrationClient(t)
	// Seeded file is "test-file.c4gh"; confirm exact match.
	files, err := client.ListFiles(context.Background(), "EGAD00000000001", apiclient.ListFilesOptions{
		ExactPath: "test-file.c4gh",
	})
	require.NoError(t, err)
	require.Len(t, files, 1)
	assert.Equal(t, "test-file.c4gh", files[0].FilePath)
}

func TestV2_ListFiles_PathPrefix_NoMatch(t *testing.T) {
	client := buildIntegrationClient(t)
	files, err := client.ListFiles(context.Background(), "EGAD00000000001", apiclient.ListFilesOptions{
		PathPrefix: "nonexistent/",
	})
	require.NoError(t, err) // 200 with empty array is the contract
	assert.Empty(t, files)
}

func TestV2_DatasetInfo_Smoke(t *testing.T) {
	client := buildIntegrationClient(t)
	info, err := client.DatasetInfo(context.Background(), "EGAD00000000001")
	require.NoError(t, err)
	assert.Equal(t, "EGAD00000000001", info.DatasetID)
	assert.Greater(t, info.FileCount, 0)
}

// TestV2_DownloadFile_EndToEnd exercises the full v2 download path against
// the dev stack: resolve test-file.c4gh via the exact filePath filter,
// follow the server-provided downloadUrl, stream the encrypted bytes.
// Requires DOWNLOAD_V2_PUBKEY_B64 (CI extracts it from the reencrypt
// container's /shared/c4gh.pub.pem).
func TestV2_DownloadFile_EndToEnd(t *testing.T) {
	client := buildIntegrationClient(t)

	pubKeyBase64 := os.Getenv("DOWNLOAD_V2_PUBKEY_B64")
	require.NotEmpty(t, pubKeyBase64, "DOWNLOAD_V2_PUBKEY_B64 must be set")

	result, err := client.DownloadFile(context.Background(), apiclient.DownloadRequest{
		DatasetID:       "EGAD00000000001",
		UserArg:         "test-file.c4gh",
		PublicKeyBase64: pubKeyBase64,
	})
	require.NoError(t, err)
	defer result.Body.Close()

	got, err := io.ReadAll(result.Body)
	require.NoError(t, err)
	assert.Greater(t, len(got), 0)
	if result.ContentLength > 0 {
		assert.Equal(t, result.ContentLength, int64(len(got)), "body size should match Content-Length")
	}
}

func TestV2_DownloadFile_NotFound403(t *testing.T) {
	client := buildIntegrationClient(t)
	pubKey := os.Getenv("DOWNLOAD_V2_PUBKEY_B64")
	require.NotEmpty(t, pubKey)

	_, err := client.DownloadFile(context.Background(), apiclient.DownloadRequest{
		DatasetID:       "EGAD00000000001",
		UserArg:         "definitely-not-a-real-file.c4gh",
		PublicKeyBase64: pubKey,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "dataset/file does not exist or access denied")
}
