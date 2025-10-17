package download

import (
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"flag"
	"fmt"
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

	httpTestServer *httptest.Server
}

func (dts *DownloadTestSuite) SetupSuite() {
	// Create a test httpTestServer
	dts.httpTestServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
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
                "fileId": "dummyFile",
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
		case "/metadata/datasets":
			// Set the response status code
			w.WriteHeader(http.StatusOK)
			// Set the response body
			fmt.Fprint(w, `["https://doi.example/ty009.sfrrss/600.45asasga"]`)
		default:
			// Set the response status code
			w.WriteHeader(http.StatusOK)
			// Set the response body
			fmt.Fprint(w, "test response")
		}
	}))

	dts.accessToken = generateDummyToken(dts.T())
}

func (dts *DownloadTestSuite) TearDownSuite() {
	dts.httpTestServer.Close()
}
func (dts *DownloadTestSuite) SetupTest() {
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
	dts.tempDir = dts.T().TempDir()

	// Create config file
	configFile, err := os.CreateTemp(os.TempDir(), "sda-cli.conf")
	if err != nil {
		dts.FailNow("failed to create config file in temporary directory", err)
	}
	dts.configFilePath = configFile.Name()

	// Write config file
	err = os.WriteFile(dts.configFilePath, []byte(fmt.Sprintf(`
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
`, dts.accessToken)), 0600)
	if err != nil {
		dts.FailNow("failed to write to config file", err)
	}
}

func TestConfigDownloadTestSuite(t *testing.T) {
	suite.Run(t, new(DownloadTestSuite))
}

func (dts *DownloadTestSuite) TestInvalidUrl() {
	err := Download([]string{
		"download",
		"-dataset-id",
		"TES01",
		"-url",
		"https://some/url",
		"file1",
		"file2",
	}, dts.configFilePath, "test-version")

	assert.Contains(
		dts.T(),
		err.Error(),
		"failed to get files, reason: failed to get response, reason: Get \"https://some/url/metadata/datasets/TES01/files\": dial tcp: lookup some",
	)
}

func (dts *DownloadTestSuite) TestDownloadOneFileNoPublicKey() {
	if err := Download([]string{
		"download",
		"-dataset-id",
		"TES01",
		"-url",
		dts.httpTestServer.URL,
		"-outdir",
		dts.tempDir,
		"files/dummy-file.txt",
	}, dts.configFilePath, "test-version"); err != nil {
		dts.FailNow("unexpected error from Download", err)
	}

	// Read the downloaded file
	downloadedContent, err := os.ReadFile(fmt.Sprintf("%s/files/dummy-file.txt", dts.tempDir))
	assert.NoError(dts.T(), err)

	// Check if the downloaded content matches the expected content
	assert.Equal(dts.T(), "test content dummy file", string(downloadedContent))
}

func (dts *DownloadTestSuite) TestDownloadMultipleFilesNoPublicKey() {
	if err := Download([]string{
		"download",
		"-dataset-id",
		"TES01",
		"-url",
		dts.httpTestServer.URL,
		"-outdir",
		dts.tempDir,
		"files/dummy-file.txt",
		"files/file1",
		"files/file2",
	}, dts.configFilePath, "test-version"); err != nil {
		dts.FailNow("unexpected error from Download", err)
	}

	// Read the downloaded file
	downloadedContent, err := os.ReadFile(fmt.Sprintf("%s/files/dummy-file.txt", dts.tempDir))
	assert.NoError(dts.T(), err)

	// Check if the downloaded content matches the expected content
	assert.Equal(dts.T(), "test content dummy file", string(downloadedContent))

	// Read the downloaded file
	downloadedContent, err = os.ReadFile(fmt.Sprintf("%s/files/file1", dts.tempDir))
	assert.NoError(dts.T(), err)

	// Check if the downloaded content matches the expected content
	assert.Equal(dts.T(), "test content file 1", string(downloadedContent))

	// Read the downloaded file
	downloadedContent, err = os.ReadFile(fmt.Sprintf("%s/files/file2", dts.tempDir))
	assert.NoError(dts.T(), err)

	// Check if the downloaded content matches the expected content
	assert.Equal(dts.T(), "test content file 2", string(downloadedContent))
}

func (dts *DownloadTestSuite) TestDownloadOneFileWithPublicKey() {
	testKeyFile := filepath.Join(dts.tempDir, "testkey")
	// generate key files
	err := createkey.GenerateKeyPair(testKeyFile, "test")
	assert.NoError(dts.T(), err)

	if err := Download([]string{
		"download",
		"-pubkey",
		fmt.Sprintf("%s.pub.pem", testKeyFile),
		"-dataset-id",
		"TES01",
		"-url",
		dts.httpTestServer.URL,
		"-outdir",
		dts.tempDir,
		"files/dummy-file.txt",
	}, dts.configFilePath, "test-version"); err != nil {
		dts.FailNow("unexpected error from Download", err)
	}

	// Read the downloaded file
	downloadedContent, err := os.ReadFile(fmt.Sprintf("%s/files/dummy-file.txt.c4gh", dts.tempDir))
	assert.NoError(dts.T(), err)

	// Check if the downloaded content matches the expected content
	assert.Equal(dts.T(), "test content dummy file", string(downloadedContent))
}

func (dts *DownloadTestSuite) TestDownloadFileAlreadyExistsWithContinue() {
	if err := os.Mkdir(path.Join(dts.tempDir, "files"), 0750); err != nil {
		dts.FailNow("failed to create temporary directory", err)
	}

	tempFile := filepath.Join(dts.tempDir, "files", "dummy-file.txt")
	if err := os.WriteFile(tempFile, []byte("NOT TO BE OVERWRITTEN"), 0600); err != nil {
		dts.FailNow("failed to write temp file", err)
	}

	if err := Download([]string{
		"download",
		"-dataset-id",
		"TES01",
		"-url",
		dts.httpTestServer.URL,
		"-outdir",
		dts.tempDir,
		"-continue",
		"files/dummy-file.txt",
	}, dts.configFilePath, "test-version"); err != nil {
		dts.FailNow("unexpected error from Download", err)
	}

	// Read the downloaded file
	downloadedContent, err := os.ReadFile(tempFile)
	require.NoError(dts.T(), err)

	// Ensure existing file has not been overwritten
	assert.Equal(dts.T(), "NOT TO BE OVERWRITTEN", string(downloadedContent))
}

func (dts *DownloadTestSuite) TestDownloadDataset() {
	if err := Download([]string{
		"download",
		"-dataset-id",
		"TES01",
		"-url",
		dts.httpTestServer.URL,
		"-outdir",
		dts.tempDir,
		"-dataset",
	}, dts.configFilePath, "test-version"); err != nil {
		dts.FailNow("unexpected error from Download", err)
	}

	// Read the downloaded file
	downloadedContent, err := os.ReadFile(fmt.Sprintf("%s/files/dummy-file.txt", dts.tempDir))
	assert.NoError(dts.T(), err)

	// Check if the downloaded content matches the expected content
	assert.Equal(dts.T(), "test content dummy file", string(downloadedContent))

	// Read the downloaded file
	downloadedContent, err = os.ReadFile(fmt.Sprintf("%s/files/file1", dts.tempDir))
	assert.NoError(dts.T(), err)

	// Check if the downloaded content matches the expected content
	assert.Equal(dts.T(), "test content file 1", string(downloadedContent))

	// Read the downloaded file
	downloadedContent, err = os.ReadFile(fmt.Sprintf("%s/files/file2", dts.tempDir))
	assert.NoError(dts.T(), err)

	// Check if the downloaded content matches the expected content
	assert.Equal(dts.T(), "test content file 2", string(downloadedContent))
}

func (dts *DownloadTestSuite) TestDownloadRecursive() {
	if err := Download([]string{
		"download",
		"-dataset-id",
		"TES01",
		"-url",
		dts.httpTestServer.URL,
		"-outdir",
		dts.tempDir,
		"-recursive",
		"files/",
	}, dts.configFilePath, "test-version"); err != nil {
		dts.FailNow("unexpected error from Download", err)
	}

	// Read the downloaded file
	downloadedContent, err := os.ReadFile(fmt.Sprintf("%s/files/dummy-file.txt", dts.tempDir))
	assert.NoError(dts.T(), err)

	// Check if the downloaded content matches the expected content
	assert.Equal(dts.T(), "test content dummy file", string(downloadedContent))

	// Read the downloaded file
	downloadedContent, err = os.ReadFile(fmt.Sprintf("%s/files/file1", dts.tempDir))
	assert.NoError(dts.T(), err)

	// Check if the downloaded content matches the expected content
	assert.Equal(dts.T(), "test content file 1", string(downloadedContent))

	// Read the downloaded file
	downloadedContent, err = os.ReadFile(fmt.Sprintf("%s/files/file2", dts.tempDir))
	assert.NoError(dts.T(), err)

	// Check if the downloaded content matches the expected content
	assert.Equal(dts.T(), "test content file 2", string(downloadedContent))
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

func (dts *DownloadTestSuite) TestGetFilesInfo() {
	files, err := GetFilesInfo(dts.httpTestServer.URL, "TES01", "", dts.accessToken, "test-version")
	require.NoError(dts.T(), err)
	require.Len(dts.T(), files, 3)
	assert.Equal(dts.T(), "file1id", files[0].FileID)
	assert.Equal(dts.T(), "file1.c4gh", files[0].DisplayFileName)
	assert.Equal(dts.T(), "files/file1.c4gh", files[0].FilePath)
	assert.Equal(dts.T(), "4293c9a7-re60-46ac-b79a-40ddc0ddd1c6", files[0].FileName)
	assert.Equal(dts.T(), "TES01", files[0].DatasetID)
	assert.Equal(dts.T(), "file2id", files[1].FileID)
	assert.Equal(dts.T(), "file2.c4gh", files[1].DisplayFileName)
	assert.Equal(dts.T(), "files/file2.c4gh", files[1].FilePath)
	assert.Equal(dts.T(), "4b40bd16-9eba-4992-af39-a7f824e612e2", files[1].FileName)
	assert.Equal(dts.T(), "TES01", files[1].DatasetID)
	assert.Equal(dts.T(), "dummyFile", files[2].FileID)
	assert.Equal(dts.T(), "dummy-file.txt.c4gh", files[2].DisplayFileName)
	assert.Equal(dts.T(), "files/dummy-file.txt.c4gh", files[2].FilePath)
	assert.Equal(dts.T(), "4b40bd16-9eba-4992-af39-a7f824e612e1", files[2].FileName)
	assert.Equal(dts.T(), "TES01", files[2].DatasetID)
}

func (dts *DownloadTestSuite) TestFileIdUrl() {
	for _, test := range []struct {
		testName, baseURL, datasetID, filePath string
		expectedURL                            string
		expectedError                          error
	}{
		{
			testName:      "ValidInputNoPubKey",
			baseURL:       dts.httpTestServer.URL,
			datasetID:     "TES01",
			filePath:      "files/file1",
			expectedURL:   fmt.Sprintf("%s/s3/TES01/files/file1.c4gh", dts.httpTestServer.URL),
			expectedError: nil,
		}, {
			testName:      "UnknownFilePath",
			baseURL:       dts.httpTestServer.URL,
			datasetID:     "TES01",
			filePath:      "files/unknown",
			expectedURL:   "",
			expectedError: errors.New("File not found in dataset files/unknown.c4gh"),
		}, {
			testName:      "FileIdInFilePath",
			baseURL:       dts.httpTestServer.URL,
			datasetID:     "TES01",
			filePath:      "file1id",
			expectedURL:   fmt.Sprintf("%s/s3/TES01/files/file1.c4gh", dts.httpTestServer.URL),
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
		dts.T().Run(test.testName, func(t *testing.T) {
			url, _, err := getFileIDURL(test.baseURL, dts.accessToken, "", test.datasetID, test.filePath)
			assert.Equal(t, test.expectedError, err)
			assert.Equal(t, test.expectedURL, url)
		})
	}
}

func (dts *DownloadTestSuite) TestGetDatasets() {
	// Test
	datasets, err := GetDatasets(dts.httpTestServer.URL, dts.accessToken, "test-version")
	require.NoError(dts.T(), err)
	assert.Equal(dts.T(), datasets, []string{"https://doi.example/ty009.sfrrss/600.45asasga"})
}

func (dts *DownloadTestSuite) TestGetBodyNoPublicKey() {
	// Make a request to the test httpTestServer with an empty public key
	body, err := getBody(dts.httpTestServer.URL, "test-token", "")
	if err != nil {
		dts.T().Errorf("getBody returned an error: %v", err)
	}

	// Check the response body
	expectedBody := "test response"
	if string(body) != expectedBody {
		dts.T().Errorf("getBody returned incorrect response body, got: %s, want: %s", string(body), expectedBody)
	}
}
func (dts *DownloadTestSuite) TestGetBodyWithPublicKey() {
	// Make a request to the test httpTestServer using a public key
	body, err := getBody(dts.httpTestServer.URL, "test-token", "test-public-key")
	if err != nil {
		dts.T().Errorf("getBody returned an error: %v", err)
	}

	// Check the response body
	expectedBody := "test response"
	if string(body) != expectedBody {
		dts.T().Errorf("getBody returned incorrect response body, got: %s, want: %s", string(body), expectedBody)
	}
}
func (dts *DownloadTestSuite) TestSetupCookiejar() {
	testCookie := filepath.Join(dts.tempDir, ".cache/sda-cli/sda_cookie")
	if runtime.GOOS == "windows" {
		testCookie = filepath.Join(dts.tempDir, "sda-cli/sda_cookie")
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
			cachePath:    dts.tempDir,
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
			cachePath:    dts.tempDir,
			cookiePath:   testCookie,
			cookieString: "[{\"Name\":\"test-cookie\", \"Value\":\"cache_path_cookie\"}]",
			createCookie: true,
			testName:     "cache_path_cookie",
		},
		{
			cachePath:    dts.tempDir,
			cookiePath:   testCookie,
			cookieString: "[{\"Name\":\"test-cookie\", \"Value\":\"test-data\",\"Domain\":\"example.org\"}]",
			createCookie: true,
			testName:     "wrong_domain",
		},
		{
			cachePath:    dts.tempDir,
			cookiePath:   testCookie,
			cookieString: "[{\"Name\":\"test-cookie\", \"Value\":\"test-data\",\"Expires\":\"2001-01-01T00:00:00Z\"}]",
			createCookie: true,
			testName:     "expired",
		},
		{
			cachePath:    dts.tempDir,
			cookiePath:   testCookie,
			cookieString: "[{\"Name\":\"test-cookie\", \"Value\":\"not_expired_cookie\",\"Expires\":\"2026-01-01T00:00:00Z\",\"MaxAge\":0}]",
			createCookie: true,
			testName:     "not_expired_cookie",
		},
		{
			cachePath:    dts.tempDir,
			cookiePath:   testCookie,
			cookieString: "[{\"Name\":\"test-cookie\", \"Value\":\"max-age_cookie\",\"Expires\":\"0001-01-01T00:00:00Z\",\"MaxAge\":300}]",
			createCookie: true,
			testName:     "max-age_cookie",
		},
	} {
		dts.T().Run(test.testName, func(t *testing.T) {
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

			u, _ := url.Parse(dts.httpTestServer.URL)
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
