package download

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"path/filepath"
	"testing"
	"time"

	"github.com/NBISweden/sda-cli/apiclient"
	createkey "github.com/NBISweden/sda-cli/create_key"
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
	testKeyFile    string

	httpTestServer *httptest.Server
}

func (s *DownloadTestSuite) SetupSuite() {
	s.httpTestServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		switch req.RequestURI {
		case "/metadata/datasets/TES01/files":
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `[
            {
                "fileId": "file1id",
				"displayFileName": "file1.c4gh",
                "filePath": "files/file1.c4gh"
            },
			{
                "fileId": "file2id",
				"displayFileName": "file2.c4gh",
                "filePath": "files/file2.c4gh"
            },
			{
                "fileId": "dummyFile",
				"displayFileName": "dummy-file.txt.c4gh",
                "filePath": "files/dummy-file.txt.c4gh"
            }
        	]`)

		case "/s3/TES01/files/dummy-file.txt.c4gh":
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "test content dummy file")
		case "/s3/TES01/files/file1.c4gh":
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "test content file 1")
		case "/s3/TES01/files/file2.c4gh":
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "test content file 2")
		case "/metadata/datasets":
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `["https://doi.example/ty009.sfrrss/600.45asasga"]`)
		default:
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "test response")
		}
	}))

	s.accessToken = generateDummyToken(s.T())
}

func (s *DownloadTestSuite) TearDownSuite() {
	s.httpTestServer.Close()
}
func (s *DownloadTestSuite) SetupTest() {
	os.Args = []string{"", "download"}
	downloadCmd.Flag("dataset-id").Value.Set("")
	downloadCmd.Flag("url").Value.Set("")
	downloadCmd.Flag("outdir").Value.Set("")
	downloadCmd.Flag("dataset").Value.Set("false")
	downloadCmd.Flag("pubkey").Value.Set("")
	downloadCmd.Flag("recursive").Value.Set("false")
	downloadCmd.Flag("from-file").Value.Set("false")
	downloadCmd.Flag("ignore-existing").Value.Set("false")
	downloadCmd.Flag("overwrite-existing").Value.Set("false")
	downloadCmd.Flag("api-version").Value.Set("v1")
	pubKeyBase64 = ""

	s.tempDir = s.T().TempDir()

	configFile, err := os.CreateTemp(os.TempDir(), "sda-cli.conf")
	if err != nil {
		s.FailNow("failed to create config file in temporary directory", err)
	}
	s.configFilePath = configFile.Name()
	downloadCmd.InheritedFlags().Set("config", s.configFilePath)

	// Write config file
	err = os.WriteFile(s.configFilePath, []byte(fmt.Sprintf(`
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
`, s.accessToken)), 0600)
	if err != nil {
		s.FailNow("failed to write to config file", err)
	}

	s.testKeyFile = filepath.Join(s.tempDir, "testkey")
	err = createkey.GenerateKeyPair(s.testKeyFile, "test")
	assert.NoError(s.T(), err)
}

func TestConfigDownloadTestSuite(t *testing.T) {
	suite.Run(t, new(DownloadTestSuite))
}

func (s *DownloadTestSuite) TestInvalidUrl() {
	os.Args = []string{"", "download", "file1", "file2"}
	downloadCmd.Flag("url").Value.Set("https://some/url")
	downloadCmd.Flag("dataset-id").Value.Set("TES01")
	err := downloadCmd.Execute()
	assert.Contains(
		s.T(),
		err.Error(),
		"failed to get response, reason: Get \"https://some/url/metadata/datasets/TES01/files\": dial tcp: lookup some",
	)
}

func (s *DownloadTestSuite) TestDownload_APIVersionV2_MissingPubkey() {
	// v2 requires --pubkey. Without one, V2Client.DownloadFile errors before
	// any HTTP request.
	oldDatasetID, oldURL, oldAPIVersion := datasetID, URL, apiVersionFlag
	datasetID = "TES01"
	URL = s.httpTestServer.URL
	apiVersionFlag = "v2"
	defer func() {
		datasetID, URL, apiVersionFlag = oldDatasetID, oldURL, oldAPIVersion
	}()

	err := Download([]string{"files/file1.c4gh"}, s.configFilePath, "test")
	require.Error(s.T(), err)
	assert.Contains(s.T(), err.Error(), "v2 downloads require --pubkey")
}

func (s *DownloadTestSuite) TestDownload_APIVersionV2_HitsV2Endpoint() {
	// v2 factory returns a real V2Client. For the single-file path, the
	// flow is downloadOne -> V2Client.DownloadFile -> resolveFile ->
	// ListFiles which issues GET /datasets/{id}/files. The mock server has
	// no v2 handler, so decoding its default non-JSON body fails — proving
	// v2 is wired up.
	oldDatasetID, oldURL, oldAPIVersion := datasetID, URL, apiVersionFlag
	datasetID = "TES01"
	URL = s.httpTestServer.URL
	apiVersionFlag = "v2"
	defer func() {
		datasetID, URL, apiVersionFlag = oldDatasetID, oldURL, oldAPIVersion
	}()

	oldPubKey := pubKey
	pubKey = fmt.Sprintf("%s.pub.pem", s.testKeyFile)
	defer func() { pubKey = oldPubKey }()

	err := Download([]string{"files/file1.c4gh"}, s.configFilePath, "test")
	require.Error(s.T(), err)
	assert.Contains(s.T(), err.Error(), "failed to decode /datasets/TES01/files response")
}

func (s *DownloadTestSuite) TestDownloadOneFileWithPublicKey() {
	os.Args = []string{"", "download", "files/dummy-file.txt.c4gh"}
	downloadCmd.Flag("pubkey").Value.Set(fmt.Sprintf("%s.pub.pem", s.testKeyFile))
	downloadCmd.Flag("url").Value.Set(s.httpTestServer.URL)
	downloadCmd.Flag("outdir").Value.Set(s.tempDir)
	downloadCmd.Flag("dataset-id").Value.Set("TES01")
	err := downloadCmd.Execute()
	if err != nil {
		s.FailNow("unexpected error from Download", err)
	}

	downloadedContent, err := os.ReadFile(fmt.Sprintf("%s/files/dummy-file.txt.c4gh", s.tempDir))
	assert.NoError(s.T(), err)
	assert.Equal(s.T(), "test content dummy file", string(downloadedContent))
}

// TestDownloadDefaultOutdir guards that the default --outdir "" writes to
// the current working directory. The previous prefix-based escape check
// rejected this case (filepath.Clean("") = "." and filepath.Join strips
// the leading "./", so strings.HasPrefix on the cleaned path was always
// false), meaning every download without --outdir failed AFTER the body
// stream was already opened on the server side.
func (s *DownloadTestSuite) TestDownloadDefaultOutdir() {
	cwd, err := os.Getwd()
	require.NoError(s.T(), err)
	runDir := filepath.Join(s.tempDir, "defaultoutdir-run")
	require.NoError(s.T(), os.MkdirAll(runDir, 0750))
	require.NoError(s.T(), os.Chdir(runDir))
	defer os.Chdir(cwd) //nolint:errcheck

	os.Args = []string{"", "download", "files/dummy-file.txt.c4gh"}
	downloadCmd.Flag("pubkey").Value.Set(fmt.Sprintf("%s.pub.pem", s.testKeyFile))
	downloadCmd.Flag("url").Value.Set(s.httpTestServer.URL)
	downloadCmd.Flag("outdir").Value.Set("") // explicit default
	downloadCmd.Flag("dataset-id").Value.Set("TES01")
	require.NoError(s.T(), downloadCmd.Execute())

	downloaded, err := os.ReadFile(filepath.Join(runDir, "files", "dummy-file.txt.c4gh"))
	require.NoError(s.T(), err)
	assert.Equal(s.T(), "test content dummy file", string(downloaded))
}

func (s *DownloadTestSuite) TestDownloadFileAlreadyExistsWithContinue() {
	if err := os.Mkdir(path.Join(s.tempDir, "files"), 0750); err != nil {
		s.FailNow("failed to create temporary directory", err)
	}

	tempFile := filepath.Join(s.tempDir, "files", "dummy-file.txt.c4gh")
	if err := os.WriteFile(tempFile, []byte("NOT TO BE OVERWRITTEN"), 0600); err != nil {
		s.FailNow("failed to write temp file", err)
	}

	os.Args = []string{"", "download", "files/dummy-file.txt.c4gh"}
	downloadCmd.Flag("pubkey").Value.Set(fmt.Sprintf("%s.pub.pem", s.testKeyFile))
	downloadCmd.Flag("ignore-existing").Value.Set("true")
	downloadCmd.Flag("url").Value.Set(s.httpTestServer.URL)
	downloadCmd.Flag("outdir").Value.Set(s.tempDir)
	downloadCmd.Flag("dataset-id").Value.Set("TES01")
	err := downloadCmd.Execute()
	if err != nil {
		s.FailNow("unexpected error from Download", err)
	}

	downloadedContent, err := os.ReadFile(tempFile)
	require.NoError(s.T(), err)
	assert.Equal(s.T(), "NOT TO BE OVERWRITTEN", string(downloadedContent))
}

func (s *DownloadTestSuite) TestDownloadDataset() {
	downloadCmd.Flag("pubkey").Value.Set(fmt.Sprintf("%s.pub.pem", s.testKeyFile))
	downloadCmd.Flag("dataset").Value.Set("true")
	downloadCmd.Flag("url").Value.Set(s.httpTestServer.URL)
	downloadCmd.Flag("outdir").Value.Set(s.tempDir)
	downloadCmd.Flag("dataset-id").Value.Set("TES01")
	err := downloadCmd.Execute()
	if err != nil {
		s.FailNow("unexpected error from Download", err)
	}

	downloadedContent, err := os.ReadFile(fmt.Sprintf("%s/files/dummy-file.txt.c4gh", s.tempDir))
	assert.NoError(s.T(), err)
	assert.Equal(s.T(), "test content dummy file", string(downloadedContent))

	downloadedContent, err = os.ReadFile(fmt.Sprintf("%s/files/file1.c4gh", s.tempDir))
	assert.NoError(s.T(), err)
	assert.Equal(s.T(), "test content file 1", string(downloadedContent))

	downloadedContent, err = os.ReadFile(fmt.Sprintf("%s/files/file2.c4gh", s.tempDir))
	assert.NoError(s.T(), err)
	assert.Equal(s.T(), "test content file 2", string(downloadedContent))
}

func (s *DownloadTestSuite) TestDownloadRecursive() {
	os.Args = []string{"", "download", "files/"}
	downloadCmd.Flag("pubkey").Value.Set(fmt.Sprintf("%s.pub.pem", s.testKeyFile))
	downloadCmd.Flag("recursive").Value.Set("true")
	downloadCmd.Flag("url").Value.Set(s.httpTestServer.URL)
	downloadCmd.Flag("outdir").Value.Set(s.tempDir)
	downloadCmd.Flag("dataset-id").Value.Set("TES01")
	err := downloadCmd.Execute()
	if err != nil {
		s.FailNow("unexpected error from Download", err)
	}

	downloadedContent, err := os.ReadFile(fmt.Sprintf("%s/files/dummy-file.txt.c4gh", s.tempDir))
	assert.NoError(s.T(), err)
	assert.Equal(s.T(), "test content dummy file", string(downloadedContent))

	downloadedContent, err = os.ReadFile(fmt.Sprintf("%s/files/file1.c4gh", s.tempDir))
	assert.NoError(s.T(), err)
	assert.Equal(s.T(), "test content file 1", string(downloadedContent))

	downloadedContent, err = os.ReadFile(fmt.Sprintf("%s/files/file2.c4gh", s.tempDir))
	assert.NoError(s.T(), err)
	assert.Equal(s.T(), "test content file 2", string(downloadedContent))
}

func generateDummyToken(t *testing.T) string {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	// Create the Claims
	claims := &jwt.StandardClaims{
		Issuer:    "test",
		ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	accessToken, err := token.SignedString(privateKey)
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}

	return accessToken
}

// errReader returns some data then an error on the next Read, so
// writeBodyToDisk triggers its cleanup defer.
type errReader struct {
	data []byte
	err  error
	sent bool
}

func (r *errReader) Read(p []byte) (int, error) {
	if !r.sent {
		r.sent = true
		n := copy(p, r.data)

		return n, nil
	}

	return 0, r.err
}

func (s *DownloadTestSuite) TestWriteBodyToDiskCleanupOnFailure() {
	destPath := filepath.Join(s.tempDir, "cleanup-test.c4gh")

	reader := &errReader{data: []byte("partial"), err: errors.New("mid-stream failure")}
	err := writeBodyToDisk(reader, int64(len("partial")+10), destPath)
	assert.Error(s.T(), err, "expected writeBodyToDisk to return an error when body errors mid-stream")

	// Final target should not exist
	_, err = os.Stat(destPath)
	assert.True(s.T(), os.IsNotExist(err), "the final target file should not exist after a failed download")

	// .part should have been cleaned up
	_, err = os.Stat(destPath + ".part")
	assert.True(s.T(), os.IsNotExist(err), "the .part file should have been removed by the defer cleanup block")
}

func (s *DownloadTestSuite) TestDownloadCleanupPartialFileWhenFullExists() {
	// We need to use a file that exists in our mock server to test through fileCase/Download
	targetFile := "files/dummy-file.txt.c4gh"
	fullPath := filepath.Join(s.tempDir, targetFile)
	partPath := fullPath + ".part"

	// Create the subdirectory first
	err := os.MkdirAll(filepath.Dir(fullPath), 0750)
	s.Require().NoError(err)

	err = os.WriteFile(fullPath, []byte("old content"), 0600)
	s.Require().NoError(err)
	err = os.WriteFile(partPath, []byte("partial content"), 0600)
	s.Require().NoError(err)

	r, w, _ := os.Pipe()
	localStdin := os.Stdin
	os.Stdin = r
	defer func() { os.Stdin = localStdin }()

	go func() {
		_, _ = w.Write([]byte("n\n"))
		_ = w.Close()
	}()

	os.Args = []string{"", "download", targetFile}
	downloadCmd.Flag("url").Value.Set(s.httpTestServer.URL)
	downloadCmd.Flag("outdir").Value.Set(s.tempDir)
	downloadCmd.Flag("dataset-id").Value.Set("TES01")

	err = downloadCmd.Execute()
	s.NoError(err)

	// Verify full content is NOT overwritten
	content, err := os.ReadFile(fullPath)
	s.NoError(err)
	s.Equal("old content", string(content))

	// Verify partial file is deleted
	_, err = os.Stat(partPath)
	s.True(os.IsNotExist(err), "The .part file should have been removed because a full file exists")
}

func (s *DownloadTestSuite) TestDownloadConflictingFlags() {
	os.Args = []string{"", "download", "files/dummy-file.txt.c4gh"}
	downloadCmd.Flag("ignore-existing").Value.Set("true")
	downloadCmd.Flag("overwrite-existing").Value.Set("true")
	downloadCmd.Flag("url").Value.Set(s.httpTestServer.URL)
	downloadCmd.Flag("outdir").Value.Set(s.tempDir)
	downloadCmd.Flag("dataset-id").Value.Set("TES01")
	err := downloadCmd.Execute()
	s.Error(err)
	s.Contains(err.Error(), "both --ignore-existing and --overwrite-existing flags are set, choose one of them")
}

// downloadOneWithClient is a small helper for TestDownloadPromptOverwrite.
// It lets the test drive downloadOne directly with a V1Client pointed at
// the suite's test server, so we can exercise the overwrite-prompt logic
// without going through downloadCmd.Execute (which has its own flag
// bookkeeping that's less ergonomic to reset between four sub-cases).
func (s *DownloadTestSuite) downloadOneWithClient(userArg string) error {
	client := apiclient.NewV1Client(apiclient.Config{
		BaseURL: s.httpTestServer.URL,
		Token:   s.accessToken,
		Version: "test",
	}, nil)
	client.SetHTTPClientForTest(s.httpTestServer.Client())

	return downloadOne(context.Background(), client, userArg)
}

func (s *DownloadTestSuite) TestDownloadPromptOverwrite() {
	targetFile := "files/dummy-file.txt.c4gh"
	expectedContent := "test content dummy file"
	fullPath := filepath.Join(s.tempDir, targetFile)
	originalStdin := os.Stdin
	defer func() { os.Stdin = originalStdin }()

	// Helper to reset flags
	resetFlags := func() {
		ignoreExisting = false
		overwriteExisting = false
	}

	oldDatasetID := datasetID
	datasetID = "TES01"
	defer func() { datasetID = oldDatasetID }()

	outDir = s.tempDir

	// Ensure parent dir exists so we can pre-populate the target
	s.Require().NoError(os.MkdirAll(filepath.Dir(fullPath), 0750))

	// Test YES
	resetFlags()
	err := os.WriteFile(fullPath, []byte("old content"), 0600)
	s.Require().NoError(err)

	r, w, _ := os.Pipe()
	os.Stdin = r
	go func() {
		_, _ = w.Write([]byte("y\n"))
		_ = w.Close()
	}()
	err = s.downloadOneWithClient(targetFile)
	s.NoError(err)

	// Verify content is overwritten
	content, err := os.ReadFile(fullPath)
	s.NoError(err)
	s.Equal(expectedContent, string(content))

	// Test NO
	resetFlags()
	err = os.WriteFile(fullPath, []byte("old content"), 0600)
	s.Require().NoError(err)

	r2, w2, _ := os.Pipe()
	os.Stdin = r2
	go func() {
		_, _ = w2.Write([]byte("n\n"))
		_ = w2.Close()
	}()

	err = s.downloadOneWithClient(targetFile)
	s.NoError(err)

	// Verify content is NOT overwritten
	content, err = os.ReadFile(fullPath)
	s.NoError(err)
	s.Equal("old content", string(content))

	// Test ALWAYS
	resetFlags()
	err = os.WriteFile(fullPath, []byte("old content"), 0600)
	s.Require().NoError(err)

	r3, w3, _ := os.Pipe()
	os.Stdin = r3
	go func() {
		_, _ = w3.Write([]byte("a\n"))
		_ = w3.Close()
	}()

	err = s.downloadOneWithClient(targetFile)
	s.NoError(err)

	// Verify content is overwritten
	s.True(overwriteExisting)
	content, err = os.ReadFile(fullPath)
	s.NoError(err)
	s.Equal(expectedContent, string(content))

	// Subsequent download (overwrite without prompting)
	err = os.WriteFile(fullPath, []byte("second old content"), 0600)
	s.Require().NoError(err)
	err = s.downloadOneWithClient(targetFile)
	s.NoError(err)
	content, err = os.ReadFile(fullPath)
	s.NoError(err)
	s.Equal(expectedContent, string(content))

	// Test NEVER
	resetFlags()
	err = os.WriteFile(fullPath, []byte("old content"), 0600)
	s.Require().NoError(err)

	r4, w4, _ := os.Pipe()
	os.Stdin = r4
	go func() {
		_, _ = w4.Write([]byte("v\n"))
		_ = w4.Close()
	}()

	err = s.downloadOneWithClient(targetFile)
	s.NoError(err)

	// Verify content is NOT overwritten
	s.True(ignoreExisting)
	content, err = os.ReadFile(fullPath)
	s.NoError(err)
	s.Equal("old content", string(content))

	// Subsequent download (skip overwrite without prompting)
	if !ignoreExisting {
		err = s.downloadOneWithClient(targetFile)
		s.NoError(err)
	}
	content, err = os.ReadFile(fullPath)
	s.NoError(err)
	s.Equal("old content", string(content))
}
