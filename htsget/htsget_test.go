package htsget

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type TestSuite struct {
	suite.Suite
}

func TestConfigTestSuite(t *testing.T) {
	suite.Run(t, new(TestSuite))
}

func (suite *TestSuite) MissingArgument() {
	os.Args = []string{"htsget"}
	err := Htsget(os.Args, "")
	assert.EqualError(suite.T(), err, "missing required arguments, dataset, filename, host and key are required")
}

// test Htsget with mocked http request

func (suite *TestSuite) TestHtsgetMissingConfig() {
	os.Args = []string{"htsget", "-dataset", "DATASET0001", "-filename", "htsnexus_test_NA12878", "-host", "somehost", "-pubkey", "somekey"}
	err := Htsget(os.Args, "nonexistent.conf")
	msg := "no such file or directory"
	if runtime.GOOS == "windows" {
		msg = "open nonexistent.conf: The system cannot find the file specified."
	}
	assert.ErrorContains(suite.T(), err, msg)
}

func (suite *TestSuite) TestHtsgetMissingPubKey() {
	tmpDir := suite.T().TempDir()
	s3cmdConf := `[default]
access_key=test_dummy.org
secret_key=test_dummy.org
check_ssl_certificate = False
encoding = UTF-8
encrypt = False
guess_mime_type = True
host_base = http://127.0.0.1:8000
host_bucket = http://127.0.0.1:8000
human_readable_sizes = True
multipart_chunk_size_mb = 50
use_https = False
socket_timeout = 30
access_token = eyJ0eXAiOiJKV1QiLCJqa3UiOiJodHRwczovL29pZGM6ODA4MC9qd2siLCJhbGciOiJFUzI1NiIsImtpZCI6IlYxcXN1VlVINUEyaTR5TWlmSFZTQWJDTTlxMnVldkF0MUktNzZfdlNTVjQifQ.eyJzdWIiOiJyZXF1ZXN0ZXJAZGVtby5vcmciLCJhdWQiOlsiYXVkMSIsImF1ZDIiXSwiYXpwIjoiYXpwIiwic2NvcGUiOiJvcGVuaWQgZ2E0Z2hfcGFzc3BvcnRfdjEiLCJpc3MiOiJodHRwczovL29pZGM6ODA4MC8iLCJleHAiOjk5OTk5OTk5OTksImlhdCI6MTU2MTYyMTkxMywianRpIjoiNmFkN2FhNDItM2U5Yy00ODMzLWJkMTYtNzY1Y2I4MGMyMTAyIn0.shY1Af3m6cPbRQd5Rn_tjvzBiJ8zx0cbsPkV8nebGrqAekpp42kUuoTYc2GCekowZMx-7J_qt3pz5Tk6nRyIHw`
	err := os.WriteFile(filepath.Join(tmpDir, "s3cmd_test.conf"), []byte(s3cmdConf), 0600)
	if err != nil {
		panic(err)
	}
	os.Args = []string{"htsget", "-dataset", "DATASET0001", "-filename", "htsnexus_test_NA12878", "-host", "somehost", "-pubkey", "somekey"}
	err = Htsget(os.Args, filepath.Join(tmpDir, "s3cmd_test.conf"))
	assert.ErrorContains(suite.T(), err, "failed to read public key")
}

func (suite *TestSuite) TestHtsgetMissingServer() {
	tmpDir := suite.T().TempDir()
	s3cmdConf := `[default]
access_key=test_dummy.org
secret_key=test_dummy.org
check_ssl_certificate = False
encoding = UTF-8
encrypt = False
guess_mime_type = True
host_base = http://127.0.0.1:8000
host_bucket = http://127.0.0.1:8000
human_readable_sizes = True
multipart_chunk_size_mb = 50
use_https = False
socket_timeout = 30
access_token = eyJ0eXAiOiJKV1QiLCJqa3UiOiJodHRwczovL29pZGM6ODA4MC9qd2siLCJhbGciOiJFUzI1NiIsImtpZCI6IlYxcXN1VlVINUEyaTR5TWlmSFZTQWJDTTlxMnVldkF0MUktNzZfdlNTVjQifQ.eyJzdWIiOiJyZXF1ZXN0ZXJAZGVtby5vcmciLCJhdWQiOlsiYXVkMSIsImF1ZDIiXSwiYXpwIjoiYXpwIiwic2NvcGUiOiJvcGVuaWQgZ2E0Z2hfcGFzc3BvcnRfdjEiLCJpc3MiOiJodHRwczovL29pZGM6ODA4MC8iLCJleHAiOjk5OTk5OTk5OTksImlhdCI6MTU2MTYyMTkxMywianRpIjoiNmFkN2FhNDItM2U5Yy00ODMzLWJkMTYtNzY1Y2I4MGMyMTAyIn0.shY1Af3m6cPbRQd5Rn_tjvzBiJ8zx0cbsPkV8nebGrqAekpp42kUuoTYc2GCekowZMx-7J_qt3pz5Tk6nRyIHw`
	err := os.WriteFile(filepath.Join(tmpDir, "s3cmd_test.conf"), []byte(s3cmdConf), 0600)
	if err != nil {
		panic(err)
	}
	pubKey := `-----BEGIN CRYPT4GH PUBLIC KEY-----
KKj6NUcJGZ2/HeqkYbxm57ZaFLP5cIHsdK+0nQubFVs=
-----END CRYPT4GH PUBLIC KEY-----`
	err = os.WriteFile(tmpDir+"c4gh.pub.pem", []byte(pubKey), 0600)
	if err != nil {
		panic(err)
	}
	os.Args = []string{"htsget", "-dataset", "DATASET0001", "-filename", "htsnexus_test_NA12878", "-host", "missingserver", "-pubkey", tmpDir + "c4gh.pub.pem"}
	err = Htsget(os.Args, filepath.Join(tmpDir, "s3cmd_test.conf"))
	assert.ErrorContains(suite.T(), err, "failed to do the request")
}

func (suite *TestSuite) TestHtsgetFailDownloadFiles() {
	tmpDir := suite.T().TempDir()
	s3cmdConf := `[default]
access_key=test_dummy.org
secret_key=test_dummy.org
check_ssl_certificate = False
encoding = UTF-8
encrypt = False
guess_mime_type = True
host_base = http://127.0.0.1:8000
host_bucket = http://127.0.0.1:8000
human_readable_sizes = True
multipart_chunk_size_mb = 50
use_https = False
socket_timeout = 30
access_token = eyJ0eXAiOiJKV1QiLCJqa3UiOiJodHRwczovL29pZGM6ODA4MC9qd2siLCJhbGciOiJFUzI1NiIsImtpZCI6IlYxcXN1VlVINUEyaTR5TWlmSFZTQWJDTTlxMnVldkF0MUktNzZfdlNTVjQifQ.eyJzdWIiOiJyZXF1ZXN0ZXJAZGVtby5vcmciLCJhdWQiOlsiYXVkMSIsImF1ZDIiXSwiYXpwIjoiYXpwIiwic2NvcGUiOiJvcGVuaWQgZ2E0Z2hfcGFzc3BvcnRfdjEiLCJpc3MiOiJodHRwczovL29pZGM6ODA4MC8iLCJleHAiOjk5OTk5OTk5OTksImlhdCI6MTU2MTYyMTkxMywianRpIjoiNmFkN2FhNDItM2U5Yy00ODMzLWJkMTYtNzY1Y2I4MGMyMTAyIn0.shY1Af3m6cPbRQd5Rn_tjvzBiJ8zx0cbsPkV8nebGrqAekpp42kUuoTYc2GCekowZMx-7J_qt3pz5Tk6nRyIHw`
	err := os.WriteFile(filepath.Join(tmpDir, "s3cmd_test.conf"), []byte(s3cmdConf), 0600)
	if err != nil {
		panic(err)
	}

	pubKey := `-----BEGIN CRYPT4GH PUBLIC KEY-----
KKj6NUcJGZ2/HeqkYbxm57ZaFLP5cIHsdK+0nQubFVs=
-----END CRYPT4GH PUBLIC KEY-----`
	err = os.WriteFile(tmpDir+"c4gh.pub.pem", []byte(pubKey), 0600)
	if err != nil {
		panic(err)
	}

	jsonData := `{
  "htsget": {
    "format": "BAM",
    "urls": [
      {
        "url": "data:;base64,Y3J5cHQ0Z2gBAAAAAgAAAA=="
      },
      {
        "url": "http://localhost/s3/DATASET0001/htsnexus_test_NA12878.bam.c4gh",
        "headers": {
          "Range": "bytes=16-123",
          "accept-encoding": "gzip",
          "authorization": "Bearer eyJ0eXAiOiJKV1QiLCJqa3UiOiJodHRwczovL29pZGM6ODA4MC9qd2siLCJhbGciOiJFUzI1NiIsImtpZCI6IlYxcXN1VlVINUEyaTR5TWlmSFZTQWJDTTlxMnVldkF0MUktNzZfdlNTVjQifQ.eyJzdWIiOiJyZXF1ZXN0ZXJAZGVtby5vcmciLCJhdWQiOlsiYXVkMSIsImF1ZDIiXSwiYXpwIjoiYXpwIiwic2NvcGUiOiJvcGVuaWQgZ2E0Z2hfcGFzc3BvcnRfdjEiLCJpc3MiOiJodHRwczovL29pZGM6ODA4MC8iLCJleHAiOjk5OTk5OTk5OTksImlhdCI6MTU2MTYyMTkxMywianRpIjoiNmFkN2FhNDItM2U5Yy00ODMzLWJkMTYtNzY1Y2I4MGMyMTAyIn0.shY1Af3m6cPbRQd5Rn_tjvzBiJ8zx0cbsPkV8nebGrqAekpp42kUuoTYc2GCekowZMx-7J_qt3pz5Tk6nRyIHw",
          "client-public-key": "LS0tLS1CRUdJTiBDUllQVDRHSCBQVUJMSUMgS0VZLS0tLS0KS0tqNk5VY0pHWjIvSGVxa1lieG01N1phRkxQNWNJSHNkSyswblF1YkZWcz0KLS0tLS1FTkQgQ1JZUFQ0R0ggUFVCTElDIEtFWS0tLS0tCg==",
          "host": "localhost:8088",
          "user-agent": "Go-http-client/1.1"
        }
      },
      {
        "url": "data:;base64,ZAAAAAAAAAB7zX5e64IzHWf5/X8nkdCKpwsX0eT4/AHU77sh2+EdIXwkSEyPQ5ZP2+vRHvytn6H1hf63Wo7gPdDc59KZfz+10kjywPqQUXYOoSbeQ6cxx2dxmf2nSwSd2Wh1jA=="
      },
      {
        "url": "http://localhost/s3/DATASET0001/htsnexus_test_NA12878.bam.c4gh",
        "headers": {
          "Range": "bytes=124-1049147",
          "accept-encoding": "gzip",
          "authorization": "Bearer eyJ0eXAiOiJKV1QiLCJqa3UiOiJodHRwczovL29pZGM6ODA4MC9qd2siLCJhbGciOiJFUzI1NiIsImtpZCI6IlYxcXN1VlVINUEyaTR5TWlmSFZTQWJDTTlxMnVldkF0MUktNzZfdlNTVjQifQ.eyJzdWIiOiJyZXF1ZXN0ZXJAZGVtby5vcmciLCJhdWQiOlsiYXVkMSIsImF1ZDIiXSwiYXpwIjoiYXpwIiwic2NvcGUiOiJvcGVuaWQgZ2E0Z2hfcGFzc3BvcnRfdjEiLCJpc3MiOiJodHRwczovL29pZGM6ODA4MC8iLCJleHAiOjk5OTk5OTk5OTksImlhdCI6MTU2MTYyMTkxMywianRpIjoiNmFkN2FhNDItM2U5Yy00ODMzLWJkMTYtNzY1Y2I4MGMyMTAyIn0.shY1Af3m6cPbRQd5Rn_tjvzBiJ8zx0cbsPkV8nebGrqAekpp42kUuoTYc2GCekowZMx-7J_qt3pz5Tk6nRyIHw",
          "client-public-key": "LS0tLS1CRUdJTiBDUllQVDRHSCBQVUJMSUMgS0VZLS0tLS0KS0tqNk5VY0pHWjIvSGVxa1lieG01N1phRkxQNWNJSHNkSyswblF1YkZWcz0KLS0tLS1FTkQgQ1JZUFQ0R0ggUFVCTElDIEtFWS0tLS0tCg==",
          "host": "localhost:8088",
          "user-agent": "Go-http-client/1.1"
        }
      },
      {
        "url": "http://localhost/s3/DATASET0001/htsnexus_test_NA12878.bam.c4gh",
        "headers": {
          "Range": "bytes=2557120-2598042",
          "accept-encoding": "gzip",
          "authorization": "Bearer eyJ0eXAiOiJKV1QiLCJqa3UiOiJodHRwczovL29pZGM6ODA4MC9qd2siLCJhbGciOiJFUzI1NiIsImtpZCI6IlYxcXN1VlVINUEyaTR5TWlmSFZTQWJDTTlxMnVldkF0MUktNzZfdlNTVjQifQ.eyJzdWIiOiJyZXF1ZXN0ZXJAZGVtby5vcmciLCJhdWQiOlsiYXVkMSIsImF1ZDIiXSwiYXpwIjoiYXpwIiwic2NvcGUiOiJvcGVuaWQgZ2E0Z2hfcGFzc3BvcnRfdjEiLCJpc3MiOiJodHRwczovL29pZGM6ODA4MC8iLCJleHAiOjk5OTk5OTk5OTksImlhdCI6MTU2MTYyMTkxMywianRpIjoiNmFkN2FhNDItM2U5Yy00ODMzLWJkMTYtNzY1Y2I4MGMyMTAyIn0.shY1Af3m6cPbRQd5Rn_tjvzBiJ8zx0cbsPkV8nebGrqAekpp42kUuoTYc2GCekowZMx-7J_qt3pz5Tk6nRyIHw",
          "client-public-key": "LS0tLS1CRUdJTiBDUllQVDRHSCBQVUJMSUMgS0VZLS0tLS0KS0tqNk5VY0pHWjIvSGVxa1lieG01N1phRkxQNWNJSHNkSyswblF1YkZWcz0KLS0tLS1FTkQgQ1JZUFQ0R0ggUFVCTElDIEtFWS0tLS0tCg==",
          "host": "localhost:8088",
          "user-agent": "Go-http-client/1.1"
        }
      }
    ]
  }
}`

	// Create a test server
	mux := http.NewServeMux()
	mux.HandleFunc("/reads/DATASET0001/htsnexus_test_NA12878", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if _, err := w.Write([]byte(jsonData)); err != nil {
			http.Error(w, "Failed to write response", http.StatusInternalServerError)
		}
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	os.Args = []string{"htsget", "-dataset", "DATASET0001", "-filename", "htsnexus_test_NA12878", "-host", server.URL, "-pubkey", tmpDir + "c4gh.pub.pem"}
	err = Htsget(os.Args, filepath.Join(tmpDir, "s3cmd_test.conf"))
	assert.ErrorContains(suite.T(), err, "error downloading the files")
}
