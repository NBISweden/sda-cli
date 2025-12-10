package htsget

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	createkey "github.com/NBISweden/sda-cli/create_key"
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

func TestHtsgetTestSuite(t *testing.T) {
	suite.Run(t, new(HtsgetTestSuite))
}

func (s *HtsgetTestSuite) SetupSuite() {
	s.httpTestServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		switch strings.Split(req.RequestURI, "?")[0] {
		case "/reads/DATASET0001/htsnexus_test_NA12878_file_not_found", "/s3/DATASET0001/htsnexus_test_NA12878_file_range_not_found.bam.c4gh":
			w.WriteHeader(http.StatusNotFound)
			_, _ = fmt.Fprint(w, "File not found")

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
}`, s.httpTestServer.URL)

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
}`, s.httpTestServer.URL)
		case "/s3/DATASET0001/htsnexus_test_NA12878.bam.c4gh":
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprintf(w, "content in range: %s", req.Header["Range"])

		default:
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = fmt.Fprint(w, "Unexpected path")
		}
	}))
}

func (s *HtsgetTestSuite) TearDownSuite() {
	s.httpTestServer.Close()
}

func (s *HtsgetTestSuite) SetupTest() {
	os.Args = []string{"", "htsget"}
	htsgetCmd.Flag("dataset").Value.Set("")
	htsgetCmd.Flag("filename").Value.Set("")
	htsgetCmd.Flag("reference").Value.Set("")
	htsgetCmd.Flag("host").Value.Set("")
	htsgetCmd.Flag("pubkey").Value.Set("")
	htsgetCmd.Flag("output").Value.Set("")
	htsgetCmd.Flag("force-overwrite").Value.Set("false")

	s.tempDir = s.T().TempDir()

	s.configPath = filepath.Join(s.tempDir, "s3cmd.conf")
	htsgetCmd.Root().Flag("config").Value.Set(s.configPath)

	if err := os.WriteFile(s.configPath, []byte(fmt.Sprintf(`
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
`, s.generateDummyToken())), 0600); err != nil {
		s.FailNow("failed to write to s3cmd.conf test file", err)
	}

	testKeyFile := filepath.Join(s.tempDir, "testkey")
	if err := createkey.GenerateKeyPair(testKeyFile, "test"); err != nil {
		s.FailNow("failed to generate key pair", err)
	}
	s.publicKeyPath = fmt.Sprintf("%s.pub.pem", testKeyFile)
}

func (s *HtsgetTestSuite) MissingArgument() {
	err := htsgetCmd.Execute()
	assert.EqualError(s.T(), err, "missing required arguments, dataset, filename, host and key are required")
}

func (s *HtsgetTestSuite) TestHtsgetMissingConfig() {
	htsgetCmd.Root().Flag("config").Value.Set("nonexistent.conf")
	htsgetCmd.Flag("dataset").Value.Set("DATASET0001")
	htsgetCmd.Flag("filename").Value.Set("htsnexus_test_NA12878")
	htsgetCmd.Flag("host").Value.Set("somehost")
	htsgetCmd.Flag("pubkey").Value.Set("somekey")
	err := htsgetCmd.Execute()

	msg := "no such file or directory"
	if runtime.GOOS == "windows" {
		msg = "open nonexistent.conf: The system cannot find the file specified."
	}
	assert.ErrorContains(s.T(), err, msg)
}

func (s *HtsgetTestSuite) TestHtsgetMissingPubKey() {
	htsgetCmd.Flag("dataset").Value.Set("DATASET0001")
	htsgetCmd.Flag("filename").Value.Set("htsnexus_test_NA12878")
	htsgetCmd.Flag("host").Value.Set("somehost")
	htsgetCmd.Flag("pubkey").Value.Set("somekey")
	err := htsgetCmd.Execute()
	assert.ErrorContains(s.T(), err, "failed to read public key")
}

func (s *HtsgetTestSuite) TestHtsgetMissingServer() {
	htsgetCmd.Flag("dataset").Value.Set("DATASET0001")
	htsgetCmd.Flag("filename").Value.Set("htsnexus_test_NA12878")
	htsgetCmd.Flag("host").Value.Set("missingserver")
	htsgetCmd.Flag("pubkey").Value.Set(s.publicKeyPath)
	err := htsgetCmd.Execute()
	assert.ErrorContains(s.T(), err, "failed to do the request")
}

func (s *HtsgetTestSuite) TestHtsgetFailReadFileInfo() {
	htsgetCmd.Flag("dataset").Value.Set("DATASET0001")
	htsgetCmd.Flag("filename").Value.Set("htsnexus_test_NA12878_file_not_found")
	htsgetCmd.Flag("host").Value.Set(s.httpTestServer.URL)
	htsgetCmd.Flag("pubkey").Value.Set(s.publicKeyPath)
	err := htsgetCmd.Execute()
	assert.ErrorContains(s.T(), err, "failed to get the file, status code: 404")
}

func (s *HtsgetTestSuite) TestHtsgetFailDownloadFileRange() {
	htsgetCmd.Flag("dataset").Value.Set("DATASET0001")
	htsgetCmd.Flag("filename").Value.Set("htsnexus_test_NA12878_file_range_not_found")
	htsgetCmd.Flag("host").Value.Set(s.httpTestServer.URL)
	htsgetCmd.Flag("pubkey").Value.Set(s.publicKeyPath)
	err := htsgetCmd.Execute()
	assert.ErrorContains(s.T(), err, "error downloading the files")
	assert.ErrorContains(s.T(), err, "404 Not Found")
}

func (s *HtsgetTestSuite) TestHtsgetWriteOutPutFile() {
	outFilePath := filepath.Join(s.tempDir, "htsnexus_test_NA12878")

	htsgetCmd.Flag("dataset").Value.Set("DATASET0001")
	htsgetCmd.Flag("filename").Value.Set("htsnexus_test_NA12878")
	htsgetCmd.Flag("output").Value.Set(outFilePath)
	htsgetCmd.Flag("host").Value.Set(s.httpTestServer.URL)
	htsgetCmd.Flag("pubkey").Value.Set(s.publicKeyPath)
	err := htsgetCmd.Execute()
	assert.NoError(s.T(), err)

	outFile, err := os.Open(outFilePath)
	if err != nil {
		s.FailNow("failed to open out file due to", err)
	}

	fileContents, err := io.ReadAll(outFile)
	if err != nil {
		s.FailNow("failed to read out file due to", err)
	}

	assert.Equal(s.T(), "crypt4gh\x01\x00\x00\x00\x02\x00\x00\x00content in range: [bytes=16-123]content in base64 data\ncontent in range: [bytes=124-1049147]content in range: [bytes=2557120-2598042]", string(fileContents))

	_ = outFile.Close()
}

func (s *HtsgetTestSuite) TestHtsgetOutPutFileAlreadyExists() {
	outFilePath := filepath.Join(s.tempDir, "htsnexus_test_NA12878")

	if err := os.WriteFile(outFilePath, []byte("file already exists"), 0600); err != nil {
		s.FailNow("failed to write out file due to", err)
	}

	htsgetCmd.Flag("dataset").Value.Set("DATASET0001")
	htsgetCmd.Flag("filename").Value.Set("htsnexus_test_NA12878")
	htsgetCmd.Flag("output").Value.Set(outFilePath)
	htsgetCmd.Flag("host").Value.Set(s.httpTestServer.URL)
	htsgetCmd.Flag("pubkey").Value.Set(s.publicKeyPath)
	err := htsgetCmd.Execute()
	assert.EqualError(s.T(), err, "error downloading the files, reason: local file already exists, use -force-overwrite to overwrite")

	outFile, err := os.Open(outFilePath)
	if err != nil {
		s.FailNow("failed to open out file due to", err)
	}

	fileContents, err := io.ReadAll(outFile)
	if err != nil {
		s.FailNow("failed to read out file due to", err)
	}

	assert.Equal(s.T(), "file already exists", string(fileContents))

	_ = outFile.Close()
}

func (s *HtsgetTestSuite) generateDummyToken() string {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		s.FailNow("failed to generate key", err)
	}

	claims := &jwt.StandardClaims{
		Issuer:    "test",
		ExpiresAt: time.Now().Add(time.Minute * 2).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	ss, err := token.SignedString(privateKey)
	if err != nil {
		s.FailNow("failed to sign token", err)
	}

	return ss
}
