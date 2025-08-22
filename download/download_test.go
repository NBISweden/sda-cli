package download

import (
	"crypto/rand"
	"crypto/rsa"
	"flag"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"path/filepath"
	"testing"
	"time"

	createKey "github.com/NBISweden/sda-cli/create_key"
	"github.com/golang-jwt/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type DownloadTestSuite struct {
	suite.Suite
	tempDir        string
	configFilePath string
	accessToken    string

	httpTestServer *httptest.Server
}

var configFormat = `
access_token = %s
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
`

func (suite *DownloadTestSuite) SetupSuite() {
	// Create a test httpTestServer
	suite.httpTestServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {

		switch req.RequestURI {
		case "/metadata/datasets/TES01/files":
			// Set the response status code
			w.WriteHeader(http.StatusOK)
			// Set the response body
			fmt.Fprint(w, `[
            {
                "fileId": "file1id",
				"datasetId": "TES01",
				"displayFileName": "file1.c4gh",
                "filePath": "files/file1.c4gh",
				"fileName": "4293c9a7-re60-46ac-b79a-40ddc0ddd1c6"
            },
			{
                "fileId": "file2id",
				"datasetId": "TES01",
				"displayFileName": "file2.c4gh",
                "filePath": "files/file2.c4gh",
				"fileName": "4b40bd16-9eba-4992-af39-a7f824e612e2"
            },
			{
                "fileId": "file2id",
				"datasetId": "TES01",
				"displayFileName": "dummy-file.txt.c4gh",
                "filePath": "files/dummy-file.txt.c4gh",
				"fileName": "4b40bd16-9eba-4992-af39-a7f824e612e1"
            }
        	]`)

		case "/s3/TES01/files/dummy-file.txt.c4gh":

			// Set the response status code
			w.WriteHeader(http.StatusOK)

			fmt.Fprint(w, "test content dummy file")

		case "/s3/TES01/files/file1.c4gh":

			// Set the response status code
			w.WriteHeader(http.StatusOK)

			fmt.Fprint(w, "test content file 1")
		case "/s3/TES01/files/file2.c4gh":

			// Set the response status code
			w.WriteHeader(http.StatusOK)

			fmt.Fprint(w, "test content file 2")

		default:
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))

	suite.accessToken = generateDummyToken(suite.T())
}

func (suite *DownloadTestSuite) TearDownSuite() {
	suite.httpTestServer.Close()
}
func (suite *DownloadTestSuite) SetupTest() {
	// Reset flags from previous test executions
	Args = flag.NewFlagSet("download", flag.ContinueOnError)
	datasetID = Args.String("dataset-id", "", "Dataset ID for the file to download.")
	URL = Args.String("url", "", "The url of the download server.")
	outDir = Args.String("outdir", "", "Directory for downloaded files.")
	datasetdownload = Args.Bool("dataset", false, "Download all the files of the dataset.")
	pubKeyPath = Args.String("pubkey", "", "Public key file to use for encryption of files to download.")
	recursiveDownload = Args.Bool("recursive", false, "Download content of the folder.")
	fromFile = Args.Bool("from-file", false, "Download files from file list.")
	pubKeyBase64 = ""
	continueDownload = Args.Bool("continue", false, "Skip existing files and continue with the rest.")

	// Create a temporary directory for our files
	suite.tempDir = suite.T().TempDir()

	// Create config file
	configFile, err := os.CreateTemp(os.TempDir(), "sda-cli.conf")
	if err != nil {
		suite.FailNow("failed to create config file in temporary directory", err)
	}
	suite.configFilePath = configFile.Name()

	// Write config file
	err = os.WriteFile(suite.configFilePath, []byte(fmt.Sprintf(configFormat, suite.accessToken)), 0600)
	if err != nil {
		suite.FailNow("failed to write to config file", err)
	}
}

func TestConfigDownloadTestSuite(t *testing.T) {
	suite.Run(t, new(DownloadTestSuite))
}

func (suite *DownloadTestSuite) TestInvalidUrl() {
	err := Download([]string{
		"download",
		"-dataset-id",
		"TES01",
		"-url",
		"https://some/url",
		"file1",
		"file2",
	}, suite.configFilePath)

	assert.Contains(
		suite.T(),
		err.Error(),
		"failed to get files, reason: failed to get response, reason: Get \"https://some/url/metadata/datasets/TES01/files\": dial tcp: lookup some",
	)
}

func (suite *DownloadTestSuite) TestDownloadOneFileNoPublicKey() {

	if err := Download([]string{
		"download",
		"-dataset-id",
		"TES01",
		"-url",
		suite.httpTestServer.URL,
		"-outdir",
		suite.tempDir,
		"files/dummy-file.txt",
	}, suite.configFilePath); err != nil {
		suite.FailNow("unexpected error from Download", err)
	}

	// Read the downloaded file
	downloadedContent, err := os.ReadFile(fmt.Sprintf("%s/files/dummy-file.txt", suite.tempDir))
	assert.NoError(suite.T(), err)

	// Check if the downloaded content matches the expected content
	assert.Equal(suite.T(), "test content dummy file", string(downloadedContent))
}

func (suite *DownloadTestSuite) TestDownloadMultipleFilesNoPublicKey() {

	if err := Download([]string{
		"download",
		"-dataset-id",
		"TES01",
		"-url",
		suite.httpTestServer.URL,
		"-outdir",
		suite.tempDir,
		"files/dummy-file.txt",
		"files/file1",
		"files/file2",
	}, suite.configFilePath); err != nil {
		suite.FailNow("unexpected error from Download", err)
	}

	// Read the downloaded file
	downloadedContent, err := os.ReadFile(fmt.Sprintf("%s/files/dummy-file.txt", suite.tempDir))
	assert.NoError(suite.T(), err)

	// Check if the downloaded content matches the expected content
	assert.Equal(suite.T(), "test content dummy file", string(downloadedContent))

	// Read the downloaded file
	downloadedContent, err = os.ReadFile(fmt.Sprintf("%s/files/file1", suite.tempDir))
	assert.NoError(suite.T(), err)

	// Check if the downloaded content matches the expected content
	assert.Equal(suite.T(), "test content file 1", string(downloadedContent))

	// Read the downloaded file
	downloadedContent, err = os.ReadFile(fmt.Sprintf("%s/files/file2", suite.tempDir))
	assert.NoError(suite.T(), err)

	// Check if the downloaded content matches the expected content
	assert.Equal(suite.T(), "test content file 2", string(downloadedContent))
}

func (suite *DownloadTestSuite) TestDownloadOneFileWithPublicKey() {
	testKeyFile := filepath.Join(suite.tempDir, "testkey")
	// generate key files
	err := createKey.GenerateKeyPair(testKeyFile, "test")
	assert.NoError(suite.T(), err)

	if err := Download([]string{
		"download",
		"-pubkey",
		fmt.Sprintf("%s.pub.pem", testKeyFile),
		"-dataset-id",
		"TES01",
		"-url",
		suite.httpTestServer.URL,
		"-outdir",
		suite.tempDir,
		"files/dummy-file.txt",
	}, suite.configFilePath); err != nil {
		suite.FailNow("unexpected error from Download", err)
	}

	// Read the downloaded file
	downloadedContent, err := os.ReadFile(fmt.Sprintf("%s/files/dummy-file.txt.c4gh", suite.tempDir))
	assert.NoError(suite.T(), err)

	// Check if the downloaded content matches the expected content
	assert.Equal(suite.T(), "test content dummy file", string(downloadedContent))
}

func (suite *DownloadTestSuite) TestDownloadFileAlreadyExistsWithContinue() {
	if err := os.Mkdir(path.Join(suite.tempDir, "files"), 0755); err != nil {
		suite.FailNow("failed to create temporary directory", err)
	}

	tempFile := filepath.Join(suite.tempDir, "files", "dummy-file.txt")
	if err := os.WriteFile(tempFile, []byte("NOT TO BE OVERWRITTEN"), 0600); err != nil {
		suite.FailNow("failed to write temp file", err)
	}

	if err := Download([]string{
		"download",
		"-dataset-id",
		"TES01",
		"-url",
		suite.httpTestServer.URL,
		"-outdir",
		suite.tempDir,
		"-continue",
		"files/dummy-file.txt",
	}, suite.configFilePath); err != nil {
		suite.FailNow("unexpected error from Download", err)
	}

	// Read the downloaded file
	downloadedContent, err := os.ReadFile(tempFile)
	require.NoError(suite.T(), err)

	// Ensure existing file has not been overwritten
	assert.Equal(suite.T(), "NOT TO BE OVERWRITTEN", string(downloadedContent))
}

func (suite *DownloadTestSuite) TestDownloadDataset() {

	if err := Download([]string{
		"download",
		"-dataset-id",
		"TES01",
		"-url",
		suite.httpTestServer.URL,
		"-outdir",
		suite.tempDir,
		"-dataset",
	}, suite.configFilePath); err != nil {
		suite.FailNow("unexpected error from Download", err)
	}

	// Read the downloaded file
	downloadedContent, err := os.ReadFile(fmt.Sprintf("%s/files/dummy-file.txt", suite.tempDir))
	assert.NoError(suite.T(), err)

	// Check if the downloaded content matches the expected content
	assert.Equal(suite.T(), "test content dummy file", string(downloadedContent))

	// Read the downloaded file
	downloadedContent, err = os.ReadFile(fmt.Sprintf("%s/files/file1", suite.tempDir))
	assert.NoError(suite.T(), err)

	// Check if the downloaded content matches the expected content
	assert.Equal(suite.T(), "test content file 1", string(downloadedContent))

	// Read the downloaded file
	downloadedContent, err = os.ReadFile(fmt.Sprintf("%s/files/file2", suite.tempDir))
	assert.NoError(suite.T(), err)

	// Check if the downloaded content matches the expected content
	assert.Equal(suite.T(), "test content file 2", string(downloadedContent))
}

func (suite *DownloadTestSuite) TestDownloadRecursive() {

	if err := Download([]string{
		"download",
		"-dataset-id",
		"TES01",
		"-url",
		suite.httpTestServer.URL,
		"-outdir",
		suite.tempDir,
		"-recursive",
		"files/",
	}, suite.configFilePath); err != nil {
		suite.FailNow("unexpected error from Download", err)
	}

	// Read the downloaded file
	downloadedContent, err := os.ReadFile(fmt.Sprintf("%s/files/dummy-file.txt", suite.tempDir))
	assert.NoError(suite.T(), err)

	// Check if the downloaded content matches the expected content
	assert.Equal(suite.T(), "test content dummy file", string(downloadedContent))

	// Read the downloaded file
	downloadedContent, err = os.ReadFile(fmt.Sprintf("%s/files/file1", suite.tempDir))
	assert.NoError(suite.T(), err)

	// Check if the downloaded content matches the expected content
	assert.Equal(suite.T(), "test content file 1", string(downloadedContent))

	// Read the downloaded file
	downloadedContent, err = os.ReadFile(fmt.Sprintf("%s/files/file2", suite.tempDir))
	assert.NoError(suite.T(), err)

	// Check if the downloaded content matches the expected content
	assert.Equal(suite.T(), "test content file 2", string(downloadedContent))
}

func generateDummyToken(t *testing.T) string {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Errorf("failed to generate key: %v", err)
		t.FailNow()
	}

	// Create the Claims
	claims := &jwt.StandardClaims{
		Issuer:    "test",
		ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	accessToken, err := token.SignedString(privateKey)
	if err != nil {
		t.Errorf("failed to sign token: %v", err)
		t.FailNow()
	}

	return accessToken

}
