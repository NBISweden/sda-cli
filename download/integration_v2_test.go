//go:build integration

package download_test

import (
	"context"
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
