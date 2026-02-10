package download

import (
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

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
                "fileId": "dummyFile",
				"datasetId": "TES01",
				"displayFileName": "dummy-file.txt.c4gh",
                "filePath": "files/dummy-file.txt.c4gh",
				"fileName": "4b40bd16-9eba-4992-af39-a7f824e612e1"
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
	downloadCmd.Flag("continue").Value.Set("false")
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

	u, _ := url.Parse("http://localhost")
	setupCookieJar(u)

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
		"failed to get files, reason: failed to get response, reason: Get \"https://some/url/metadata/datasets/TES01/files\": dial tcp: lookup some",
	)
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
	downloadCmd.Flag("continue").Value.Set("true")
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

func (s *DownloadTestSuite) TestGetFilesInfo() {
	files, err := GetFilesInfo(s.httpTestServer.URL, "TES01", "", s.accessToken, "test-version")
	require.NoError(s.T(), err)
	require.Len(s.T(), files, 3)
	assert.Equal(s.T(), "file1id", files[0].FileID)
	assert.Equal(s.T(), "file1.c4gh", files[0].DisplayFileName)
	assert.Equal(s.T(), "files/file1.c4gh", files[0].FilePath)
	assert.Equal(s.T(), "4293c9a7-re60-46ac-b79a-40ddc0ddd1c6", files[0].FileName)
	assert.Equal(s.T(), "TES01", files[0].DatasetID)
	assert.Equal(s.T(), "file2id", files[1].FileID)
	assert.Equal(s.T(), "file2.c4gh", files[1].DisplayFileName)
	assert.Equal(s.T(), "files/file2.c4gh", files[1].FilePath)
	assert.Equal(s.T(), "4b40bd16-9eba-4992-af39-a7f824e612e2", files[1].FileName)
	assert.Equal(s.T(), "TES01", files[1].DatasetID)
	assert.Equal(s.T(), "dummyFile", files[2].FileID)
	assert.Equal(s.T(), "dummy-file.txt.c4gh", files[2].DisplayFileName)
	assert.Equal(s.T(), "files/dummy-file.txt.c4gh", files[2].FilePath)
	assert.Equal(s.T(), "4b40bd16-9eba-4992-af39-a7f824e612e1", files[2].FileName)
	assert.Equal(s.T(), "TES01", files[2].DatasetID)
}

func (s *DownloadTestSuite) TestFileIdUrl() {
	for _, test := range []struct {
		testName, baseURL, datasetID, filePath string
		expectedURL                            string
		expectedError                          error
	}{
		{
			testName:      "ValidInputNoPubKey",
			baseURL:       s.httpTestServer.URL,
			datasetID:     "TES01",
			filePath:      "files/file1",
			expectedURL:   fmt.Sprintf("%s/s3/TES01/files/file1.c4gh", s.httpTestServer.URL),
			expectedError: nil,
		}, {
			testName:      "UnknownFilePath",
			baseURL:       s.httpTestServer.URL,
			datasetID:     "TES01",
			filePath:      "files/unknown",
			expectedURL:   "",
			expectedError: errors.New("File not found in dataset files/unknown.c4gh"),
		}, {
			testName:      "FileIdInFilePath",
			baseURL:       s.httpTestServer.URL,
			datasetID:     "TES01",
			filePath:      "file1id",
			expectedURL:   fmt.Sprintf("%s/s3/TES01/files/file1.c4gh", s.httpTestServer.URL),
			expectedError: nil,
		}, {
			testName:      "InvalidUrl",
			baseURL:       "some/url",
			datasetID:     "TES01",
			filePath:      "file1id",
			expectedURL:   "",
			expectedError: errors.New("invalid base URL"),
		},
	} {
		s.T().Run(test.testName, func(t *testing.T) {
			url, _, err := getFileIDURL(test.baseURL, s.accessToken, "", test.datasetID, test.filePath)
			assert.Equal(t, test.expectedError, err)
			assert.Equal(t, test.expectedURL, url)
		})
	}
}

func (s *DownloadTestSuite) TestGetDatasets() {
	datasets, err := GetDatasets(s.httpTestServer.URL, s.accessToken, "test-version")
	require.NoError(s.T(), err)
	assert.Equal(s.T(), datasets, []string{"https://doi.example/ty009.sfrrss/600.45asasga"})
}

func (s *DownloadTestSuite) TestGetBodyNoPublicKey() {
	bodyStream, size, err := getBody(s.httpTestServer.URL, "test-token", "")
	if err != nil {
		s.T().Errorf("getBody returned an error: %v", err)

		return // Exit early if there's an error to avoid nil pointer panics below
	}

	defer bodyStream.Close()

	body, err := io.ReadAll(bodyStream)
	if err != nil {
		s.T().Errorf("failed to read from bodyStream: %v", err)
	}

	expectedBody := "test response"
	if string(body) != expectedBody {
		s.T().Errorf("getBody returned incorrect response body, got: %s, want: %s", string(body), expectedBody)
	}

	if size != int64(len(expectedBody)) && size != -1 {
		s.T().Logf("Note: size returned (%d) does not match expected length (%d)", size, len(expectedBody))
	}
}

func (s *DownloadTestSuite) TestGetBodyWithPublicKey() {
	bodyStream, _, err := getBody(s.httpTestServer.URL, "test-token", "test-public-key")

	if err != nil {
		s.T().Fatalf("getBody returned an error: %v", err)
	}

	defer bodyStream.Close()

	body, err := io.ReadAll(bodyStream)
	if err != nil {
		s.T().Fatalf("failed to read from bodyStream: %v", err)
	}

	expectedBody := "test response"
	if string(body) != expectedBody {
		s.T().Errorf("getBody returned incorrect response body, got: %s, want: %s", string(body), expectedBody)
	}
}

func (s *DownloadTestSuite) TestGetBodyPreconditionFailed() {
	// Test the specific 412 logic where the body becomes the error message
	errorMessage := "error message with precondition failed"
	errorServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusPreconditionFailed)
		fmt.Fprint(w, errorMessage)
	}))
	defer errorServer.Close()

	bodyStream, size, err := getBody(errorServer.URL, "test-token", "")

	assert.Nil(s.T(), bodyStream) // On error, the stream should be nil
	assert.Equal(s.T(), int64(0), size)
	assert.Error(s.T(), err)
	assert.Equal(s.T(), errorMessage, err.Error())
}

func (s *DownloadTestSuite) TestSetupCookiejar() {
	var testCookie string
	switch runtime.GOOS {
	case "windows":
		testCookie = filepath.Join(s.tempDir, "sda-cli", "sda_cookie")
	case "darwin": // macOS
		testCookie = filepath.Join(s.tempDir, "Library", "Caches", "sda-cli", "sda_cookie")
	default: // Linux and others
		testCookie = filepath.Join(s.tempDir, ".cache", "sda-cli", "sda_cookie")
	}
	pwdCookie, _ := filepath.Abs(".sda_cookie")
	for _, test := range []struct {
		cachePath     string
		cookiePath    string
		cookieString  string
		createCookie  bool
		expectedError error
		testName      string
	}{
		{
			cachePath:    s.tempDir,
			cookiePath:   testCookie,
			cookieString: "",
			createCookie: false,
			testName:     "cookie_file_doesn't_exist",
		},
		{
			cachePath:    "",
			cookiePath:   pwdCookie,
			cookieString: "[{\"Name\":\"test-cookie\", \"Value\":\"current_dir_cookie\"}]",
			createCookie: true,
			testName:     "current_dir_cookie",
		},
		{
			cachePath:    s.tempDir,
			cookiePath:   testCookie,
			cookieString: "[{\"Name\":\"test-cookie\", \"Value\":\"cache_path_cookie\"}]",
			createCookie: true,
			testName:     "cache_path_cookie",
		},
		{
			cachePath:    s.tempDir,
			cookiePath:   testCookie,
			cookieString: "[{\"Name\":\"test-cookie\", \"Value\":\"test-data\",\"Domain\":\"example.org\"}]",
			createCookie: true,
			testName:     "wrong_domain",
		},
		{
			cachePath:    s.tempDir,
			cookiePath:   testCookie,
			cookieString: "[{\"Name\":\"test-cookie\", \"Value\":\"test-data\",\"Expires\":\"2001-01-01T00:00:00Z\"}]",
			createCookie: true,
			testName:     "expired",
		},
		{
			cachePath:    s.tempDir,
			cookiePath:   testCookie,
			cookieString: fmt.Sprintf("[{\"Name\":\"test-cookie\", \"Value\":\"not_expired_cookie\",\"Expires\":\"%s\",\"MaxAge\":0}]", time.Now().AddDate(1, 0, 0).Format(time.RFC3339)),
			createCookie: true,
			testName:     "not_expired_cookie",
		},
		{
			cachePath:    s.tempDir,
			cookiePath:   testCookie,
			cookieString: "[{\"Name\":\"test-cookie\", \"Value\":\"max-age_cookie\",\"Expires\":\"0001-01-01T00:00:00Z\",\"MaxAge\":300}]",
			createCookie: true,
			testName:     "max-age_cookie",
		},
	} {
		s.T().Run(test.testName, func(t *testing.T) {
			if runtime.GOOS == "windows" {
				os.Setenv("LocalAppData", test.cachePath)
			} else {
				os.Setenv("HOME", test.cachePath)
			}
			if test.createCookie {
				cookieFile, _ := filepath.Abs(test.cookiePath)
				if err := os.WriteFile(cookieFile, []byte(test.cookieString), 0600); err != nil {
					fmt.Fprintln(os.Stderr, "failed to save cookie file ", err.Error())
				}
			}

			u, _ := url.Parse(s.httpTestServer.URL)
			setupCookieJar(u)
			assert.Equal(t, test.cookiePath, cookiePath)
			cj := cookieJar.Cookies(u)

			if strings.HasSuffix(test.testName, "cookie") {
				assert.Equal(t, "test-cookie", cj[0].Name)
				assert.Equal(t, test.testName, cj[0].Value)
				assert.Equal(t, "0001-01-01T00:00:00Z", cj[0].Expires.Format(time.RFC3339))
				_ = os.Remove(cookiePath)
			} else {
				assert.Nil(t, cj)
			}
		})
	}
}

func (s *DownloadTestSuite) TestDownloadCleanupOnFailure() {
	failServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, "server error")
	}))
	defer failServer.Close()

	targetFile := "cleanup-test.c4gh"
	fullPath := filepath.Join(s.tempDir, targetFile)

	downloadCmd.Flag("continue").Value.Set("false")
	outDir = s.tempDir

	err := downloadFile(failServer.URL, s.accessToken, "", targetFile)
	assert.Error(s.T(), err, "Expected downloadFile to return an error on 500 response")

	// Check that the .part file was cleaned up
	_, err = os.Stat(fullPath + ".part")
	assert.True(s.T(), os.IsNotExist(err), "The .part file should have been removed by the defer cleanup block")

	// Check that the final target file was not created
	_, err = os.Stat(fullPath)
	assert.True(s.T(), os.IsNotExist(err), "The final target file should not exist after a failed download")
}
