package download

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetFilesInfo(t *testing.T) {
	// Create a test httpTestServer
	httpTestServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		// Set the response status code
		w.WriteHeader(http.StatusOK)
		// Set the response body
		fmt.Fprint(w, `[
            {
                "fileId": "file1id",
				"datasetId": "TES01",
				"displayFileName": "file1",
                "filePath": "path/to/file1",
				"fileName": "4293c9a7-re60-46ac-b79a-40ddc0ddd1c6"
            },
			{
                "fileId": "file2id",
				"datasetId": "TES01",
				"displayFileName": "file2",
                "filePath": "path/to/file2",
				"fileName": "4b40bd16-9eba-4992-af39-a7f824e612e2"
            }
        ]`)
	}))
	defer httpTestServer.Close()

	// Test
	files, err := GetFilesInfo(httpTestServer.URL, "test-dataset", "", accessToken)
	require.NoError(t, err)
	require.Len(t, files, 2)
	assert.Equal(t, "file1id", files[0].FileID)
	assert.Equal(t, "file1", files[0].DisplayFileName)
	assert.Equal(t, "path/to/file1", files[0].FilePath)
	assert.Equal(t, "4293c9a7-re60-46ac-b79a-40ddc0ddd1c6", files[0].FileName)
	assert.Equal(t, "TES01", files[0].DatasetID)
	assert.Equal(t, "file2id", files[1].FileID)
	assert.Equal(t, "file2", files[1].DisplayFileName)
	assert.Equal(t, "path/to/file2", files[1].FilePath)
	assert.Equal(t, "4b40bd16-9eba-4992-af39-a7f824e612e2", files[1].FileName)
	assert.Equal(t, "TES01", files[1].DatasetID)
}
