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

// TestV2_ListDatasets_Smoke calls the real v2 dev stack. Requires:
//   - dev-tools/download-v2-dev/ stack is up (make dev-download-v2-up)
//   - DOWNLOAD_V2_URL env var (default http://localhost:8085)
//   - DOWNLOAD_V2_TOKEN env var (dev token from mockauth)
func TestV2_ListDatasets_Smoke(t *testing.T) {
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

	got, err := client.ListDatasets(context.Background())
	require.NoError(t, err)
	assert.Contains(t, got, "EGAD00000000001", "dev stack should expose seeded dataset EGAD00000000001")
}
