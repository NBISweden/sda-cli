package download

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type TestSuite struct {
	suite.Suite
	accessToken string
}

func createConfigFile(fileName, token string) os.File {
	// Create conf file for sda-cli
	confFile := fmt.Sprintf(`
	access_token = %[1]s
	host_base = inbox.dummy.org
	encoding = UTF-8
	host_bucket = inbox.dummy.org
	multipart_chunk_size_mb = 50
	secret_key = dummy
	access_key = dummy
	use_https = False
	check_ssl_certificate = False
	check_ssl_hostname = False
	socket_timeout = 30
	human_readable_sizes = True
	guess_mime_type = True
	encrypt = False
	`, token)

	// Create config file
	configPath, err := os.CreateTemp(os.TempDir(), fileName)
	if err != nil {
		log.Panic(err)
	}

	// Write config file
	err = os.WriteFile(configPath.Name(), []byte(confFile), 0600)
	if err != nil {
		log.Printf("failed to write temp config file, %v", err)
	}

	return *configPath
}

func TestConfigTestSuite(t *testing.T) {
	suite.Run(t, new(TestSuite))
}

func (suite *TestSuite) SetupTest() {
	suite.accessToken = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImtleXN0b3JlLUNIQU5HRS1NRSJ9.eyJqdGkiOiJWTWpfNjhhcEMxR2FJbXRZdFExQ0ciLCJzdWIiOiJkdW1teSIsImlzcyI6Imh0dHA6Ly9vaWRjOjkwOTAiLCJpYXQiOjE3MDc3NjMyODksImV4cCI6MTg2NTU0NzkxOSwic2NvcGUiOiJvcGVuaWQgZ2E0Z2hfcGFzc3BvcnRfdjEgcHJvZmlsZSBlbWFpbCIsImF1ZCI6IlhDNTZFTDExeHgifQ.ZFfIAOGeM2I5cvqr1qJV74qU65appYjpNJVWevGHjGA5Xk_qoRMFJXmG6AiQnYdMKnJ58sYGNjWgs2_RGyw5NyM3-pgP7EKHdWU4PrDOU84Kosg4IPMSFxbBRAEjR5X04YX_CLYW2MFk_OyM9TIln522_JBVT_jA5WTTHSmBRHntVArYYHvQdF-oFRiqL8JXWlsUBh3tqQ33sZdqd9g64YhTk9a5lEC42gn5Hg9Hm_qvkl5orzEqIg7x9z5706IBE4Zypco5ohrAKsEbA8EKbEBb0jigGgCslQNde2owUyKIkvZYmxHA78X5xpymMp9K--PgbkyMS9GtA-YwOHPs-w"
}

func (suite *TestSuite) TestInvalidUrl() {
	confPath := createConfigFile("s3cmd.conf", suite.accessToken)

	os.Args = []string{
		"download",
		"-dataset-id",
		"TES01",
		"-config",
		confPath.Name(),
		"-url",
		"https://some/url",
		"file1",
		"file2",
	}

	err := Download(os.Args)
	assert.Contains(
		suite.T(),
		err.Error(),
		"failed to get files, reason: failed to get response, reason: Get \"https://some/url/metadata/datasets/TES01/files\": dial tcp: lookup some",
	)
}

func (suite *TestSuite) TestGetBody() {
	// Create a test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Set the response status code
		w.WriteHeader(http.StatusOK)
		// Set the response body
		fmt.Fprint(w, "test response")
	}))
	defer server.Close()

	// Make a request to the test server with an empty public key
	body, err := getBody(server.URL, "test-token", "")
	if err != nil {
		suite.T().Errorf("getBody returned an error: %v", err)
	}

	// Check the response body
	expectedBody := "test response"
	if string(body) != expectedBody {
		suite.T().
			Errorf("getBody returned incorrect response body, got: %s, want: %s", string(body), expectedBody)
	}

	// Make a request to the test server using a public key
	body, err = getBody(server.URL, "test-token", "test-public-key")
	if err != nil {
		suite.T().Errorf("getBody returned an error: %v", err)
	}

	// Check the response body
	expectedBody = "test response"
	if string(body) != expectedBody {
		suite.T().
			Errorf("getBody returned incorrect response body, got: %s, want: %s", string(body), expectedBody)
	}
}

func (suite *TestSuite) TestDownloadUrl() {
	// Mock getBody function
	defer func() { getResponseBody = getBody }()
	getResponseBody = func(_, _, _ string) ([]byte, error) {
		return []byte(`[
            {
                "fileId": "file1id",
				"datasetId": "TES01",
				"displayName": "file1",
                "filePath": "path/to/file1.c4gh",
				"fileName": "4293c9a7-re60-46ac-b79a-40ddc0ddd1c6"
            }
        ]`), nil
	}

	baseURL := "https://some/url"
	token := suite.accessToken
	datasetID := "test-dataset"
	filepath := "path/to/file1"
	expectedURL := "https://some/url/files/file1id"

	//-----------------------------------------------
	// Test with an empty public key

	// Test with valid base_url, token, dataset, and filename
	url, _, err := getFileIDURL(baseURL, token, "", datasetID, filepath)
	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), expectedURL, url)

	// Test with url as dataset
	datasetID = "https://doi.example/another/url/001"
	_, _, err = getFileIDURL(baseURL, token, "", datasetID, filepath)
	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), expectedURL, url)

	// Test with filename not in response
	filepath = "path/to/file2"
	_, _, err = getFileIDURL(baseURL, token, "", datasetID, filepath)
	assert.Error(suite.T(), err)

	// Test with fileID
	filepath = "file1id"
	_, _, err = getFileIDURL(baseURL, token, "", datasetID, filepath)
	assert.NoError(suite.T(), err)

	// Testr with bad URL
	_, _, err = getFileIDURL("some/url", token, "", datasetID, filepath)
	assert.Error(suite.T(), err)

	//-----------------------------------------------
	// Test using a nonempty public key
	// Test with valid base_url, token, dataset, and filename
	expectedURL = baseURL + "/s3-encrypted/" + datasetID + "/" + filepath
	pubKey := "test-public-key"
	url, _, err = getFileIDURL(baseURL, token, pubKey, datasetID, filepath)
	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), expectedURL, url)

	// Test with url as dataset
	datasetID = "https://doi.example/another/url/001"
	expectedURL = baseURL + "/s3-encrypted/" + datasetID + "/" + filepath
	url, _, err = getFileIDURL(baseURL, token, pubKey, datasetID, filepath)
	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), expectedURL, url)

	// Test with filename not in response
	filepath = "path/to/file2"
	_, _, err = getFileIDURL(baseURL, token, pubKey, datasetID, filepath)
	assert.Error(suite.T(), err)

	// Testr with bad URL
	_, _, err = getFileIDURL("some/url", token, pubKey, datasetID, filepath)
	assert.Error(suite.T(), err)
}

func (suite *TestSuite) TestDownloadFile() {
	// Create a temporary directory for testing
	tempDir := suite.T().TempDir()

	// Create a temporary file for testing
	tempFile := filepath.Join(tempDir, "dummy-file.txt")
	err := os.WriteFile(tempFile, []byte("test content"), 0600)
	require.NoError(suite.T(), err)

	// Create a test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Set the response status code
		w.WriteHeader(http.StatusOK)
		// Set the response body
		fmt.Fprint(w, "dummy response")
	}))
	defer server.Close()

	// Call the downloadFile function without a public key
	err = downloadFile(server.URL, "test-token", "", tempFile)
	require.NoError(suite.T(), err)

	// Read the downloaded file
	downloadedContent, err := os.ReadFile(tempFile)
	require.NoError(suite.T(), err)

	// Check if the downloaded content matches the expected content
	expectedContent := "dummy response"
	assert.Equal(suite.T(), expectedContent, string(downloadedContent))

	// Call the downloadFile function with a public key
	err = downloadFile(server.URL, "test-token", "test-public-key", tempFile)
	require.NoError(suite.T(), err)

	// Read the downloaded file
	downloadedContent, err = os.ReadFile(tempFile)
	require.NoError(suite.T(), err)

	// Check if the downloaded content matches the expected content
	expectedContent = "dummy response"
	assert.Equal(suite.T(), expectedContent, string(downloadedContent))
}

func (suite *TestSuite) TestGetFilesInfo() {
	// Mock getBody function
	defer func() { getResponseBody = getBody }()
	getResponseBody = func(_, _, _ string) ([]byte, error) {
		return []byte(`[
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
        ]`), nil
	}

	// Test
	token := suite.accessToken
	baseURL := "https://some/url"
	datasetID := "test-dataset"
	files, err := GetFilesInfo(baseURL, datasetID, "", token)
	require.NoError(suite.T(), err)
	require.Len(suite.T(), files, 2)
	assert.Equal(suite.T(), "file1id", files[0].FileID)
	assert.Equal(suite.T(), "file1", files[0].DisplayFileName)
	assert.Equal(suite.T(), "path/to/file1", files[0].FilePath)
	assert.Equal(suite.T(), "4293c9a7-re60-46ac-b79a-40ddc0ddd1c6", files[0].FileName)
	assert.Equal(suite.T(), "TES01", files[0].DatasetID)
	assert.Equal(suite.T(), "file2id", files[1].FileID)
	assert.Equal(suite.T(), "file2", files[1].DisplayFileName)
	assert.Equal(suite.T(), "path/to/file2", files[1].FilePath)
	assert.Equal(suite.T(), "4b40bd16-9eba-4992-af39-a7f824e612e2", files[1].FileName)
	assert.Equal(suite.T(), "TES01", files[1].DatasetID)
}

func (suite *TestSuite) TestGetDatasets() {
	// Mock getBody function
	defer func() { getResponseBody = getBody }()
	getResponseBody = func(_, _, _ string) ([]byte, error) {
		return []byte(`["https://doi.example/ty009.sfrrss/600.45asasga"]`), nil
	}

	// Test
	token := suite.accessToken
	baseURL := "https://some/url"
	datasets, err := GetDatasets(baseURL, token)
	require.NoError(suite.T(), err)
	// assert.Contains(suite.T(), datasets, "https://doi.example/ty009.sfrrss/600.45asasga")
	assert.Equal(suite.T(), datasets, []string{"https://doi.example/ty009.sfrrss/600.45asasga"})
}
