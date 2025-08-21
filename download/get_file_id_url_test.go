package download

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFileIdUrl(t *testing.T) {

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Set the response status code
		w.WriteHeader(http.StatusOK)
		// Set the response body
		fmt.Fprint(w, `[
            {
                "fileId": "file1id",
				"datasetId": "TES01",
				"displayName": "file1",
                "filePath": "path/to/file1.c4gh",
				"fileName": "4293c9a7-re60-46ac-b79a-40ddc0ddd1c6"
            }
        ]`)
	}))
	defer server.Close()

	for _, test := range []struct {
		testName, baseURL, datasetId, filePath string
		expectedURL                            string
		expectedError                          error
	}{
		{
			testName:      "ValidInputNoPubKey",
			baseURL:       server.URL,
			datasetId:     "test-dataset",
			filePath:      "path/to/file1",
			expectedURL:   fmt.Sprintf("%s/s3/test-dataset/path/to/file1.c4gh", server.URL),
			expectedError: nil,
		}, {
			testName:      "UnknownFilePath",
			baseURL:       server.URL,
			datasetId:     "test-dataset",
			filePath:      "path/to/file2",
			expectedURL:   "",
			expectedError: fmt.Errorf("File not found in dataset path/to/file2.c4gh"),
		}, {
			testName:      "FileIdInFilePath",
			baseURL:       server.URL,
			datasetId:     "test-dataset",
			filePath:      "file1id",
			expectedURL:   fmt.Sprintf("%s/s3/test-dataset/path/to/file1.c4gh", server.URL),
			expectedError: nil,
		}, {
			testName:      "InvalidUrl",
			baseURL:       "some/url",
			datasetId:     "test-dataset",
			filePath:      "file1id",
			expectedURL:   "",
			expectedError: fmt.Errorf("invalid base URL"),
		},
	} {
		t.Run(test.testName, func(t *testing.T) {
			url, _, err := getFileIDURL(test.baseURL, accessToken, "", test.datasetId, test.filePath)
			assert.Equal(t, test.expectedError, err)
			assert.Equal(t, test.expectedURL, url)
		})
	}

}
