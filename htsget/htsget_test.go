package htsget

import (
	"crypto/rand"
	"crypto/rsa"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	createKey "github.com/NBISweden/sda-cli/create_key"
	"github.com/golang-jwt/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type HtsgetTestSuite struct {
	suite.Suite

	tempDir    string
	configPath string

	publicKeyPath string

	httpTestServer *httptest.Server
}

var configFormat = `
access_token = %[1]s
host_base = http://127.0.0.1:8000
encoding = UTF-8
host_bucket = http://127.0.0.1:8000
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

func TestHtsgetTestSuite(t *testing.T) {
	suite.Run(t, new(HtsgetTestSuite))
}

func (suite *HtsgetTestSuite) SetupSuite() {
	// Create a test http mock Server
	suite.httpTestServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {

		switch req.RequestURI {
		case "/reads/DATASET0001/htsnexus_test_NA12878_file_not_found":
			w.WriteHeader(http.StatusNotFound)
			_, _ = fmt.Fprintf(w, "File not found")

		case "/reads/DATASET0001/htsnexus_test_NA12878_file_range_not_found":
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprintf(w, `{
  "htsget": {
    "format": "BAM",
    "urls": [
      {
        "url": "%[1]s/s3/DATASET0001/htsnexus_test_NA12878_file_range_not_found.bam.c4gh",
        "headers": {
          "Range": "bytes=16-123",
          "accept-encoding": "gzip",
          "host": "%[1]s",
          "user-agent": "Go-http-client/1.1"
        }
      }
    ]
  }
}`, suite.httpTestServer.URL)

		case "/s3/DATASET0001/htsnexus_test_NA12878_file_range_not_found.bam.c4gh":
			w.WriteHeader(http.StatusNotFound)
			_, _ = fmt.Fprintf(w, "File not found")

		case "/reads/DATASET0001/htsnexus_test_NA12878":
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprintf(w, `{
  "htsget": {
    "format": "BAM",
    "urls": [
      {
        "url": "data:;base64,Y3J5cHQ0Z2gBAAAAAgAAAA=="
      },
      {
        "url": "%[1]s/s3/DATASET0001/htsnexus_test_NA12878.bam.c4gh",
        "headers": {
          "Range": "bytes=16-123"
        }
      },
      {
        "url": "data:;base64,Y29udGVudCBpbiBiYXNlNjQgZGF0YQo="
      },
      {
        "url": "%[1]s/s3/DATASET0001/htsnexus_test_NA12878.bam.c4gh",
        "headers": {
          "Range": "bytes=124-1049147"
        }
      },
      {
        "url": "%[1]s/s3/DATASET0001/htsnexus_test_NA12878.bam.c4gh",
        "headers": {
          "Range": "bytes=2557120-2598042"
        }
      }
    ]
  }
}`, suite.httpTestServer.URL)
		case "/s3/DATASET0001/htsnexus_test_NA12878.bam.c4gh":
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprintf(w, "content in range: %s", req.Header["Range"])

		default:
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = fmt.Fprint(w, "Unexpected path")
		}
	}))

}

func (suite *HtsgetTestSuite) TearDownSuite() {
	suite.httpTestServer.Close()
}

func (suite *HtsgetTestSuite) SetupTest() {
	// Reset flag values from previous test invocations
	Args = flag.NewFlagSet("htsget", flag.ContinueOnError)
	datasetID = Args.String("dataset", "", "Dataset ID for the file to download")
	fileName = Args.String("filename", "", "The name of the file to download")
	referenceName = Args.String("reference", "", "The reference number of the file to download")
	htsgetHost = Args.String("host", "", "The host to download from")
	publicKeyFile = Args.String("pubkey", "", "Public key file")
	outPut = Args.String("output", "", "Name for the downloaded file.")
	forceOverwrite = Args.Bool("force-overwrite", false, "Force overwrite existing files.")

	suite.tempDir = suite.T().TempDir()

	// Create config file
	suite.configPath = path.Join(suite.tempDir, "s3cmd.conf")

	// Write config file
	if err := os.WriteFile(suite.configPath, []byte(fmt.Sprintf(configFormat, suite.generateDummyToken())), 0600); err != nil {
		suite.FailNow("failed to write to s3cmd.conf test file", err)
	}

	testKeyFile := filepath.Join(suite.tempDir, "testkey")
	// generate key files
	if err := createKey.GenerateKeyPair(testKeyFile, "test"); err != nil {
		suite.FailNow("failed to generate key pair", err)
	}
	suite.publicKeyPath = fmt.Sprintf("%s.pub.pem", testKeyFile)
}

func (suite *HtsgetTestSuite) MissingArgument() {
	err := Htsget([]string{"htsget"}, "")
	assert.EqualError(suite.T(), err, "missing required arguments, dataset, filename, host and key are required")
}

// test Htsget with mocked http request

func (suite *HtsgetTestSuite) TestHtsgetMissingConfig() {
	err := Htsget([]string{
		"htsget",
		"-dataset",
		"DATASET0001",
		"-filename",
		"htsnexus_test_NA12878",
		"-host",
		"somehost",
		"-pubkey",
		"somekey",
	}, "nonexistent.conf")
	msg := "no such file or directory"
	if runtime.GOOS == "windows" {
		msg = "open nonexistent.conf: The system cannot find the file specified."
	}
	assert.ErrorContains(suite.T(), err, msg)
}

func (suite *HtsgetTestSuite) TestHtsgetMissingPubKey() {
	err := Htsget([]string{
		"htsget",
		"-dataset",
		"DATASET0001",
		"-filename",
		"htsnexus_test_NA12878",
		"-host",
		"somehost",
		"-pubkey",
		"somekey",
	}, suite.configPath)
	assert.ErrorContains(suite.T(), err, "failed to read public key")
}

func (suite *HtsgetTestSuite) TestHtsgetMissingServer() {
	err := Htsget([]string{
		"htsget",
		"-dataset",
		"DATASET0001",
		"-filename",
		"htsnexus_test_NA12878",
		"-host",
		"missingserver",
		"-pubkey",
		suite.publicKeyPath,
	}, suite.configPath)
	assert.ErrorContains(suite.T(), err, "failed to do the request")
}

func (suite *HtsgetTestSuite) TestHtsgetFailReadFileInfo() {
	outFilePath := fmt.Sprintf("%s/htsnexus_test_NA12878", suite.tempDir)

	err := Htsget([]string{
		"htsget",
		"-dataset",
		"DATASET0001",
		"-filename",
		"htsnexus_test_NA12878_file_not_found",
		"-output",
		outFilePath,
		"-host",
		suite.httpTestServer.URL,
		"-pubkey",
		suite.publicKeyPath,
	}, suite.configPath)
	assert.ErrorContains(suite.T(), err, "failed to get the file, status code: 404")
}

func (suite *HtsgetTestSuite) TestHtsgetFailDownloadFileRange() {
	outFilePath := fmt.Sprintf("%s/htsnexus_test_NA12878", suite.tempDir)

	err := Htsget([]string{
		"htsget",
		"-dataset",
		"DATASET0001",
		"-filename",
		"htsnexus_test_NA12878_file_range_not_found",
		"-output",
		outFilePath,
		"-host",
		suite.httpTestServer.URL,
		"-pubkey",
		suite.publicKeyPath,
	}, suite.configPath)
	assert.ErrorContains(suite.T(), err, "error downloading the files")
	assert.ErrorContains(suite.T(), err, "404 Not Found")
}

func (suite *HtsgetTestSuite) TestHtsget() {
	outFilePath := fmt.Sprintf("%s/htsnexus_test_NA12878", suite.tempDir)

	err := Htsget([]string{
		"htsget",
		"-dataset",
		"DATASET0001",
		"-filename",
		"htsnexus_test_NA12878",
		"-output",
		outFilePath,
		"-host",
		suite.httpTestServer.URL,
		"-pubkey",
		suite.publicKeyPath,
	}, suite.configPath)
	assert.NoError(suite.T(), err)

	outFile, err := os.Open(outFilePath)
	if err != nil {
		suite.FailNow("failed to open out file due to", err)
	}

	fileContents, err := io.ReadAll(outFile)
	if err != nil {
		suite.FailNow("failed to read out file due to", err)
	}

	assert.Equal(suite.T(), "crypt4gh\x01\x00\x00\x00\x02\x00\x00\x00content in range: [bytes=16-123]content in base64 data\ncontent in range: [bytes=124-1049147]content in range: [bytes=2557120-2598042]", string(fileContents))

	_ = outFile.Close()
}

func (suite *HtsgetTestSuite) TestHtsgetOutPutFileAlreadyExists() {
	outFilePath := fmt.Sprintf("%s/htsnexus_test_NA12878", suite.tempDir)

	if err := os.WriteFile(outFilePath, []byte("file already exists"), 0600); err != nil {
		suite.FailNow("failed to write out file due to", err)
	}

	err := Htsget([]string{
		"htsget",
		"-dataset",
		"DATASET0001",
		"-filename",
		"htsnexus_test_NA12878",
		"-output",
		outFilePath,
		"-host",
		suite.httpTestServer.URL,
		"-pubkey",
		suite.publicKeyPath,
	}, suite.configPath)
	assert.EqualError(suite.T(), err, "error downloading the files, reason: local file already exists, use -force-overwrite to overwrite")

	outFile, err := os.Open(outFilePath)
	if err != nil {
		suite.FailNow("failed to open out file due to", err)
	}

	fileContents, err := io.ReadAll(outFile)
	if err != nil {
		suite.FailNow("failed to read out file due to", err)
	}

	assert.Equal(suite.T(), "file already exists", string(fileContents))

	_ = outFile.Close()
}

func (suite *HtsgetTestSuite) generateDummyToken() string {
	// Generate a new private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		suite.FailNow("failed to generate key", err)
	}

	// Create the Claims
	claims := &jwt.StandardClaims{
		Issuer:    "test",
		ExpiresAt: time.Now().Add(time.Minute * 2).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	ss, err := token.SignedString(privateKey)
	if err != nil {
		suite.FailNow("failed to sign token", err)
	}

	return ss
}
