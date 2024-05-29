package sdadownload

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

func TestConfigTestSuite(t *testing.T) {
	suite.Run(t, new(TestSuite))
}

func (suite *TestSuite) SetupTest() {
	suite.accessToken = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImtleXN0b3JlLUNIQU5HRS1NRSJ9.eyJqdGkiOiJWTWpfNjhhcEMxR2FJbXRZdFExQ0ciLCJzdWIiOiJkdW1teSIsImlzcyI6Imh0dHA6Ly9vaWRjOjkwOTAiLCJpYXQiOjE3MDc3NjMyODksImV4cCI6MTg2NTU0NzkxOSwic2NvcGUiOiJvcGVuaWQgZ2E0Z2hfcGFzc3BvcnRfdjEgcHJvZmlsZSBlbWFpbCIsImF1ZCI6IlhDNTZFTDExeHgifQ.ZFfIAOGeM2I5cvqr1qJV74qU65appYjpNJVWevGHjGA5Xk_qoRMFJXmG6AiQnYdMKnJ58sYGNjWgs2_RGyw5NyM3-pgP7EKHdWU4PrDOU84Kosg4IPMSFxbBRAEjR5X04YX_CLYW2MFk_OyM9TIln522_JBVT_jA5WTTHSmBRHntVArYYHvQdF-oFRiqL8JXWlsUBh3tqQ33sZdqd9g64YhTk9a5lEC42gn5Hg9Hm_qvkl5orzEqIg7x9z5706IBE4Zypco5ohrAKsEbA8EKbEBb0jigGgCslQNde2owUyKIkvZYmxHA78X5xpymMp9K--PgbkyMS9GtA-YwOHPs-w"
}

func (suite *TestSuite) TestNoArgument() {

	os.Args = []string{"sda-download"}

	err := SdaDownload(os.Args)
	assert.EqualError(suite.T(), err, "missing required arguments, dataset, config and url are required")
}

func (suite *TestSuite) TestNoFiles() {

	os.Args = []string{"sda-download", "-dataset", "TES01", "-config", "s3cmd", "-url", "https://some/url"}

	err := SdaDownload(os.Args)
	assert.EqualError(suite.T(), err, "no files to download")
}

func (suite *TestSuite) TestInvalidUrl() {

	// Create conf file for sda-cli
	var confFile = fmt.Sprintf(`
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
	`, suite.accessToken)

	// Create config file
	configPath, err := os.CreateTemp(os.TempDir(), "s3cmd.conf")
	if err != nil {
		log.Panic(err)
	}
	defer os.Remove(configPath.Name())

	// Write config file
	err = os.WriteFile(configPath.Name(), []byte(confFile), 0600)
	if err != nil {
		log.Printf("failed to write temp config file, %v", err)
	}

	os.Args = []string{"sda-download", "-dataset", "TES01", "-config", configPath.Name(), "-url", "https://some/url", "file1", "file2"}

	err = SdaDownload(os.Args)
	assert.EqualError(suite.T(), err, "failed to get files, reason: failed to get response, reason: Get \"https://some/url/metadata/datasets/TES01/files\": dial tcp: lookup some: no such host")
}

func (suite *TestSuite) TestGetBody() {
	// Create a test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Set the response status code
		w.WriteHeader(http.StatusOK)
		// Set the response body
		fmt.Fprint(w, "test response")
	}))
	defer server.Close()

	// Make a request to the test server
	body, err := getBody(server.URL, "test-token")
	if err != nil {
		suite.T().Errorf("getBody returned an error: %v", err)
	}

	// Check the response body
	expectedBody := "test response"
	if string(body) != expectedBody {
		suite.T().Errorf("getBody returned incorrect response body, got: %s, want: %s", string(body), expectedBody)
	}
}

func (suite *TestSuite) TestDownloadUrl() {
	// Mock getBody function
	defer func() { getResponseBody = getBody }()
	getResponseBody = func(url, token string) ([]byte, error) {
		return []byte(`[
            {
                "fileId": "file1",
                "filePath": "path/to/file1"
            }
        ]`), nil
	}

	// Test with valid base_url, token, dataset, and filename
	base_url := "https://some/url"
	token := suite.accessToken
	dataset := "TES01"
	filename := "file1"
	expectedUrl := "https://some/url/files/file1"
	url, err := downloadUrl(base_url, token, dataset, filename)
	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), expectedUrl, url)

	// Test with filename not in response
	filename = "file2"
	_, err = downloadUrl(base_url, token, dataset, filename)
	assert.Error(suite.T(), err)
}

func (suite *TestSuite) TestDownloadFile() {
	// Create a temporary directory for testing
	tempDir := suite.T().TempDir()

	// Create a temporary file for testing
	tempFile := filepath.Join(tempDir, "dummy-file.txt")
	err := os.WriteFile(tempFile, []byte("test content"), 0644)
	require.NoError(suite.T(), err)

	// Create a test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Set the response status code
		w.WriteHeader(http.StatusOK)
		// Set the response body
		fmt.Fprint(w, "dummy response")
	}))
	defer server.Close()

	// Call the downloadFile function
	err = downloadFile(server.URL, "test-token", tempFile)
	require.NoError(suite.T(), err)

	// Read the downloaded file
	downloadedContent, err := os.ReadFile(tempFile)
	require.NoError(suite.T(), err)

	// Check if the downloaded content matches the expected content
	expectedContent := "dummy response"
	assert.Equal(suite.T(), expectedContent, string(downloadedContent))
}