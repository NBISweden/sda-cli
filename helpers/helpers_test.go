package helpers

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"io"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/golang-jwt/jwt"
	"github.com/johannesboyne/gofakes3"
	"github.com/johannesboyne/gofakes3/backend/s3mem"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type HelperTests struct {
	suite.Suite
	tempDir     string
	testFile    *os.File
	testFile1   *os.File
	accessToken string
}

// generate jwts for testing the expDate
func (s *HelperTests) generateDummyToken(expDate int64) string {
	// Generate a new private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		s.FailNow("failed to generate key", err)
	}

	// Create the Claims
	claims := &jwt.StandardClaims{
		Issuer: "test",
	}
	if expDate != 0 {
		claims = &jwt.StandardClaims{
			ExpiresAt: expDate,
			Issuer:    "test",
		}
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	ss, err := token.SignedString(privateKey)
	if err != nil {
		s.FailNow("failed to sign token", err)
	}

	return ss
}

func TestHelpersTestSuite(t *testing.T) {
	suite.Run(t, new(HelperTests))
}

func (s *HelperTests) SetupTest() {
	var err error

	// Create a temporary directory for our files
	s.tempDir, err = os.MkdirTemp(os.TempDir(), "sda-cli-test-")
	if err != nil {
		s.FailNow("failed to create temp test directory", err)
	}

	// create an existing test file with some known content
	s.testFile, err = os.CreateTemp(s.tempDir, "testfile-")
	if err != nil {
		s.FailNow("failed to create temp test file", err)
	}

	err = os.WriteFile(s.testFile.Name(), []byte("content"), 0600)
	if err != nil {
		s.FailNow("failed to write to test file", err)
	}

	// create another existing test file with some known content
	s.testFile1, err = os.CreateTemp(s.tempDir, "testfile-")
	if err != nil {
		s.FailNow("failed to create temp test file", err)
	}

	err = os.WriteFile(s.testFile1.Name(), []byte("more content"), 0600)
	if err != nil {
		s.FailNow("failed to write to test file", err)
	}

	s.accessToken = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImtleXN0b3JlLUNIQU5HRS1NRSJ9.eyJqdGkiOiJWTWpfNjhhcEMxR2FJbXRZdFExQ0ciLCJzdWIiOiJkdW1teSIsImlzcyI6Imh0dHA6Ly9vaWRjOjkwOTAiLCJpYXQiOjE3MDc3NjMyODksImV4cCI6MTg2NTU0NzkxOSwic2NvcGUiOiJvcGVuaWQgZ2E0Z2hfcGFzc3BvcnRfdjEgcHJvZmlsZSBlbWFpbCIsImF1ZCI6IlhDNTZFTDExeHgifQ.ZFfIAOGeM2I5cvqr1qJV74qU65appYjpNJVWevGHjGA5Xk_qoRMFJXmG6AiQnYdMKnJ58sYGNjWgs2_RGyw5NyM3-pgP7EKHdWU4PrDOU84Kosg4IPMSFxbBRAEjR5X04YX_CLYW2MFk_OyM9TIln522_JBVT_jA5WTTHSmBRHntVArYYHvQdF-oFRiqL8JXWlsUBh3tqQ33sZdqd9g64YhTk9a5lEC42gn5Hg9Hm_qvkl5orzEqIg7x9z5706IBE4Zypco5ohrAKsEbA8EKbEBb0jigGgCslQNde2owUyKIkvZYmxHA78X5xpymMp9K--PgbkyMS9GtA-YwOHPs-w"
}

func (s *HelperTests) TearDownTest() {
	os.Remove(s.testFile.Name())  //nolint:errcheck
	os.Remove(s.testFile1.Name()) //nolint:errcheck
	os.Remove(s.tempDir)          //nolint:errcheck
}

func (s *HelperTests) TestFileExists() {
	// file exists
	testExists := FileExists(s.testFile.Name())
	s.Equal(testExists, true)
	// file does not exists
	testMissing := FileExists("does-not-exist")
	s.Equal(testMissing, false)
	// file is a directory
	testIsDir := FileExists(s.tempDir)
	s.Equal(testIsDir, true)
}

func (s *HelperTests) TestFileIsReadable() {
	// file doesn't exist
	testMissing := FileIsReadable("does-not-exist")
	s.Equal(testMissing, false)

	// file is a directory
	testIsDir := FileIsReadable(s.tempDir)
	s.Equal(testIsDir, false)

	// file can be read
	testFileOk := FileIsReadable(s.testFile.Name())
	s.Equal(testFileOk, true)

	// test file permissions. This doesn't work on windows, so we do an extra
	// check to see if this test makes sense.
	if runtime.GOOS != "windows" {
		err := os.Chmod(s.testFile.Name(), 0000)
		if err != nil {
			s.FailNow("failed to chmod test file", err)
		}
		// file permissions don't allow reading
		testDisallowed := FileIsReadable(s.testFile.Name())
		s.Equal(testDisallowed, false)

		// restore permissions
		err = os.Chmod(s.testFile.Name(), 0600)
		if err != nil {
			s.FailNow("failed to chmod test file", err)
		}
	}
}

func (s *HelperTests) TestParseS3ErrorResponse() {
	// check bad response body by creating and passing
	// a dummy faulty io.Reader
	f, _ := os.Open(`doesn't exist`)
	defer f.Close() //nolint:errcheck
	msg, err := ParseS3ErrorResponse(f)
	s.Equal("", msg)
	s.ErrorContains(err, "failed to read from response body")

	// check not xml
	payload := strings.NewReader("some non xml text")
	msg, err = ParseS3ErrorResponse(payload)
	s.Equal("", msg)
	s.EqualError(err, "cannot parse response body, reason: not xml")

	// check with malformed xml
	payload.Reset("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<Error><ed</Code><Message>All access to this bucket has been disabled.</Message><Resource>/minio/test/dummy/data_file1.c4gh</Resource><RequestId></RequestId><HostId>73e4c710-46e8-4846-b70b-86ee905a3ab0</HostId></Error>")
	msg, err = ParseS3ErrorResponse(payload)
	s.Equal("", msg)
	s.ErrorContains(err, "failed to unmarshal xml response")

	// check with good xml
	payload.Reset("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<Error><Code>AllAccessDisabled</Code><Message>All access to this bucket has been disabled.</Message><Resource>/minio/test/dummy/data_file1.c4gh</Resource><RequestId></RequestId><HostId>73e4c710-46e8-4846-b70b-86ee905a3ab0</HostId></Error>")
	msg, err = ParseS3ErrorResponse(payload)
	s.Equal("{Code:AllAccessDisabled Message:All access to this bucket has been disabled. Resource:/minio/test/dummy/data_file1.c4gh}", msg)
	s.NoError(err)
}

func (s *HelperTests) TestConfigNoFile() {
	msg := "open nofile.conf: no such file or directory"
	if runtime.GOOS == "windows" {
		msg = "open nofile.conf: The system cannot find the file specified."
	}
	configPath := "nofile.conf"

	_, err := LoadConfigFile(configPath)
	assert.EqualError(s.T(), err, msg)
}

func (s *HelperTests) TestLoadConfigHostBase() {
	confFileFormat := `
	host_base = %s
	encoding = UTF-8
	host_bucket = someHostBucket
	multipart_chunk_size_mb = 50
	secret_key = dummy
	access_key = dummy
	use_https = %t
	check_ssl_certificate = False
	check_ssl_hostname = False
	socket_timeout = 30
	human_readable_sizes = True
	guess_mime_type = True
	encrypt = False
	`

	for _, test := range []struct {
		testName, inputHostBase, expectedHostBase string
		inputUseHTTPS, expectedUseHTTPS           bool
		expectedError                             error
	}{
		{
			testName:         "HttpsHostBaseUseHttpsFalse",
			inputHostBase:    "https://example.com",
			expectedHostBase: "https://example.com",
			inputUseHTTPS:    false,
			expectedUseHTTPS: true,
			expectedError:    nil,
		}, {
			testName:         "HttpHostBaseUseHttpsTrue",
			inputHostBase:    "http://example.com",
			expectedHostBase: "https://example.com",
			inputUseHTTPS:    true,
			expectedUseHTTPS: true,
			expectedError:    nil,
		}, {
			testName:         "NoSchemeHostBaseUseHttpsTrue",
			inputHostBase:    "example.com",
			expectedHostBase: "https://example.com",
			inputUseHTTPS:    true,
			expectedUseHTTPS: true,
			expectedError:    nil,
		}, {
			testName:         "NoSchemeHostBaseUseHttpsFalse",
			inputHostBase:    "example.com",
			expectedHostBase: "http://example.com",
			inputUseHTTPS:    false,
			expectedUseHTTPS: false,
			expectedError:    nil,
		}, {
			testName:         "HttpsHostBaseWithPort",
			inputHostBase:    "https://example.com:8001",
			expectedHostBase: "https://example.com:8001",
			inputUseHTTPS:    false,
			expectedUseHTTPS: true,
			expectedError:    nil,
		}, {
			testName:         "NoSchemeHostBaseAsIPWithPort",
			inputHostBase:    "127.0.0.1:8001",
			expectedHostBase: "",
			inputUseHTTPS:    false,
			expectedUseHTTPS: false,
			expectedError:    errors.New("failed to parse host base from configuration file, reason: parse \"127.0.0.1:8001\": first path segment in URL cannot contain colon"),
		}, {
			testName:         "HostBaseAsIPWithHttpSchemeAndPort",
			inputHostBase:    "http://127.0.0.1:8001",
			expectedHostBase: "http://127.0.0.1:8001",
			inputUseHTTPS:    false,
			expectedUseHTTPS: false,
			expectedError:    nil,
		}, {
			testName:         "HostBaseAsIPWithHttpsSchemeAndPort",
			inputHostBase:    "https://127.0.0.1:8001",
			expectedHostBase: "https://127.0.0.1:8001",
			inputUseHTTPS:    false,
			expectedUseHTTPS: true,
			expectedError:    nil,
		}, {
			testName:         "HostBaseAsLocalHostWithPort",
			inputHostBase:    "localhost:8000",
			expectedHostBase: "",
			inputUseHTTPS:    false,
			expectedUseHTTPS: false,
			expectedError:    errors.New("failed to parse host base from configuration file, reason: a valid host can not be parsed"),
		},
	} {
		s.T().Run(test.testName, func(t *testing.T) {
			configPath, err := os.CreateTemp(os.TempDir(), "sda-cli-helper-test-")
			if err != nil {
				s.FailNow("failed to create temporary directory", err)
			}
			defer os.RemoveAll(configPath.Name()) //nolint:errcheck

			err = os.WriteFile(configPath.Name(), []byte(fmt.Sprintf(confFileFormat, test.inputHostBase, test.inputUseHTTPS)), 0600)
			if err != nil {
				s.FailNow("failed to write config file", err)
			}

			conf, err := LoadConfigFile(configPath.Name())
			assert.Equal(t, test.expectedError, err)
			if conf == nil {
				assert.Equal(t, test.expectedHostBase, "")
				assert.Equal(t, test.expectedUseHTTPS, false)

				return
			}

			assert.Equal(t, test.expectedHostBase, conf.HostBase)
			assert.Equal(t, test.expectedUseHTTPS, conf.UseHTTPS)
		})
	}
}

func (s *HelperTests) TestConfigWrongFile() {
	var confFile = `
access_token = someToken
access_key = someUser
host_bucket = someHostBase
guess_mime_type!True
encrypt = False
`

	configPath, err := os.CreateTemp(os.TempDir(), "s3cmd-")
	if err != nil {
		s.FailNow("failed to create temp s3cmd test file", err)
	}

	defer os.Remove(configPath.Name()) //nolint:errcheck

	err = os.WriteFile(configPath.Name(), []byte(confFile), 0600)
	if err != nil {
		s.FailNow("failed to write config file", err)
	}

	_, err = LoadConfigFile(configPath.Name())
	assert.EqualError(s.T(), err, "key-value delimiter not found: guess_mime_type!True\n")
}

func (s *HelperTests) TestConfigS3cmdFileFormat() {
	var confFile = `
	[some header]
	access_token = someToken
	host_base = someHostBase
	host_bucket = someHostBase
	secret_key = someUser
	access_key = someUser
`

	configPath, err := os.CreateTemp(os.TempDir(), "s3cmd-")
	if err != nil {
		s.FailNow("failed to create temp s3cmd test file", err)
	}

	defer os.Remove(configPath.Name()) //nolint:errcheck

	err = os.WriteFile(configPath.Name(), []byte(confFile), 0600)
	if err != nil {
		s.FailNow("failed to write config file", err)
	}

	_, err = LoadConfigFile(configPath.Name())
	assert.NoError(s.T(), err)
}

func (s *HelperTests) TestConfigMissingCredentials() {
	configPath, err := os.CreateTemp(os.TempDir(), "s3cmd-")
	if err != nil {
		s.FailNow("failed to create temp s3cmd test file", err)
	}

	defer os.Remove(configPath.Name()) //nolint:errcheck

	_, err = LoadConfigFile(configPath.Name())
	assert.EqualError(s.T(), err, "failed to find credentials in configuration file")
}

func (s *HelperTests) TestConfigMissingEndpoint() {
	var confFile = `
access_token = someToken
access_key = someUser
`
	configPath, err := os.CreateTemp(os.TempDir(), "s3cmd-")
	if err != nil {
		s.FailNow("failed to create temp s3cmd test file", err)
	}

	defer os.Remove(configPath.Name()) //nolint:errcheck

	if err := os.WriteFile(configPath.Name(), []byte(confFile), 0600); err != nil {
		s.FailNow("failed to write to temp s3cmd test file", err)
	}

	_, err = LoadConfigFile(configPath.Name())
	assert.EqualError(s.T(), err, "failed to find endpoint in configuration file")
}

func (s *HelperTests) TestConfig() {
	var confFile = `
access_token = someToken
host_base = someHostBase
encoding = UTF-8
host_bucket = someHostBase
multipart_chunk_size_mb = 50
secret_key = someUser
access_key = someUser
use_https = True
check_ssl_certificate = False
check_ssl_hostname = False
socket_timeout = 30
human_readable_sizes = True
guess_mime_type = True
encrypt = False
`
	configPath, err := os.CreateTemp(os.TempDir(), "s3cmd-")
	if err != nil {
		s.FailNow("failed to create temp s3cmd test file", err)
	}

	defer os.Remove(configPath.Name()) //nolint:errcheck

	err = os.WriteFile(configPath.Name(), []byte(confFile), 0600)
	if err != nil {
		s.FailNow("failed to write to temp s3cmd test file", err)
	}

	_, err = LoadConfigFile(configPath.Name())
	assert.NoError(s.T(), err)
}

func (s *HelperTests) TestTokenExpiration() {
	// Token without exp claim
	token := s.generateDummyToken(0)
	err := CheckTokenExpiration(token)
	assert.EqualError(s.T(), err, "could not parse token, reason: no expiration date")

	// Token with expired date
	token = s.generateDummyToken(time.Now().Unix())
	err = CheckTokenExpiration(token)
	assert.EqualError(s.T(), err, "the provided access token has expired, please renew it")

	// Token with valid expiration, less than 2 hours
	token = s.generateDummyToken(time.Now().Add(time.Hour).Unix())

	storeStderr := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w

	err = CheckTokenExpiration(token)
	assert.NoError(s.T(), err)

	_ = w.Close()
	out, _ := io.ReadAll(r)
	os.Stderr = storeStderr

	msg := "WARNING! The provided access token expires in only 59 minutes."
	assert.Contains(s.T(), string(out), msg)

	// Token with valid expiration, more than a day
	exp := time.Now().Add(time.Hour * 72)
	token = s.generateDummyToken(exp.Unix())

	storeStderr = os.Stderr
	r, w, _ = os.Pipe()
	os.Stderr = w

	err = CheckTokenExpiration(token)
	assert.NoError(s.T(), err)

	_ = w.Close()
	out, _ = io.ReadAll(r)
	os.Stderr = storeStderr

	msg = "The provided access token expires on " + exp.Format(time.RFC1123)
	assert.Contains(s.T(), string(out), msg)
}

func (s *HelperTests) TestPubKeyEmptyField() {
	var confFile = `
access_token = someToken
host_base = someHostBase
encoding = UTF-8
host_bucket = someHostBase
multipart_chunk_size_mb = 50
secret_key = someUser
access_key = someUser
use_https = True
check_ssl_certificate = False
check_ssl_hostname = False
socket_timeout = 30
human_readable_sizes = True
guess_mime_type = True
encrypt = False
`
	configPath, err := os.Create(".sda-cli-session")
	if err != nil {
		s.FailNow("failed to create sda cli session test file", err)
	}

	defer os.Remove(configPath.Name()) //nolint:errcheck

	err = os.WriteFile(configPath.Name(), []byte(confFile), 0600)
	if err != nil {
		s.FailNow("failed to write to sda cli session test file", err)
	}

	_, err = GetPublicKeyFromSession()
	assert.EqualError(s.T(), err, "public key not found in the configuration")
}

func (s *HelperTests) TestGetPublicKeyFromSession() {
	var confFile = `
access_token = someToken
host_base = someHostBase
encoding = UTF-8
host_bucket = someHostBase
multipart_chunk_size_mb = 50
secret_key = someUser
access_key = someUser
use_https = True
check_ssl_certificate = False
check_ssl_hostname = False
socket_timeout = 30
human_readable_sizes = True
guess_mime_type = True
encrypt = False
public_key = 27be42445fd9e39c9be39e6b36a55e61e3801fc845f63781a813d3fe9977e17a
`
	configPath, err := os.Create(".sda-cli-session")
	if err != nil {
		s.FailNow("failed to create sda cli session test file", err)
	}

	defer os.Remove(configPath.Name()) //nolint:errcheck

	err = os.WriteFile(configPath.Name(), []byte(confFile), 0600)
	if err != nil {
		s.FailNow("failed to write to sda cli session test file", err)
	}

	_, err = GetPublicKeyFromSession()
	assert.NoError(s.T(), err)

	if assert.FileExists(s.T(), "key-from-oidc.pub.pem") {
		os.Remove("key-from-oidc.pub.pem") //nolint:errcheck
	}
}

func (s *HelperTests) TestInvalidCharacters() {
	// Test that file paths with invalid characters trigger errors
	for _, badc := range "\x00\x7F\x1A:*?\\<>\"|!'();@&=+$,%#[]" {
		badchar := string(badc)
		testfilepath := "test" + badchar + "file"

		err := CheckValidChars(testfilepath)
		assert.Error(s.T(), err)
		assert.Equal(s.T(), fmt.Sprintf("filepath %v contains disallowed characters: %+v", testfilepath, badchar), err.Error())
	}
}

func (s *HelperTests) TestCreatePubFile() {
	var pubKeyContent = `339eb2a458fec5e23aa8b57cfcb35f10e7389025816e44d4234f814ed2aeed3f`
	var expectedPubKey = `-----BEGIN CRYPT4GH PUBLIC KEY-----
MzM5ZWIyYTQ1OGZlYzVlMjNhYThiNTdjZmNiMzVmMTA=
-----END CRYPT4GH PUBLIC KEY-----
`
	_, err := CreatePubFile(pubKeyContent, os.TempDir()+"/test_public_file.pub.pem")
	assert.NoError(s.T(), err)

	pubFile, _ := os.ReadFile(os.TempDir() + "/test_public_file.pub.pem")
	assert.Equal(s.T(), expectedPubKey, string(pubFile))
	defer os.Remove(os.TempDir() + "/test_public_file.pub.pem") //nolint:errcheck
}

func (s *HelperTests) TestListFiles() {
	ctx := context.TODO()
	// Create a fake s3 backend
	backend := s3mem.New()
	faker := gofakes3.New(backend)
	ts := httptest.NewServer(faker.Server())
	defer ts.Close()

	awsConfig, err := config.LoadDefaultConfig(ctx,
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider("dummy", "dummy", s.accessToken)),
		config.WithRegion("eu-central-1"),
		config.WithBaseEndpoint(ts.URL),
	)
	if err != nil {
		s.FailNow("failed to create aws config", err)
	}

	s3Client := s3.NewFromConfig(awsConfig, func(o *s3.Options) {
		o.UsePathStyle = true
		o.EndpointOptions.DisableHTTPS = true
	})

	// Create bucket named dummy
	cparams := &s3.CreateBucketInput{
		Bucket: aws.String("dummy"),
	}
	_, err = s3Client.CreateBucket(ctx, cparams)
	if err != nil {
		s.FailNow("failed to create s3 bucket", err)
	}

	// Upload two test files
	file, err := os.Open(s.testFile.Name())
	if err != nil {
		s.FailNow("failed to open test file", err)
	}
	defer file.Close() //nolint:errcheck

	_, err = s3Client.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String("dummy"),
		Key:    aws.String("dummy/" + filepath.Base(s.testFile.Name())),
		Body:   file,
	})
	if err != nil {
		s.FailNow("failed to put test file to s3 bucket", err)
	}

	file1, err := os.Open(s.testFile1.Name())
	if err != nil {
		s.FailNow("failed to open test file", err)
	}
	defer file1.Close() //nolint:errcheck
	_, err = s3Client.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String("dummy"),
		Key:    aws.String("dummy/" + filepath.Base(s.testFile1.Name())),
		Body:   file1,
	})
	if err != nil {
		s.FailNow("failed to put test file to s3 bucket", err)
	}

	testConfig := &Config{
		AccessToken: s.accessToken,
		AccessKey:   "dummy",
		SecretKey:   "dummy",
		HostBase:    ts.URL,
		UseHTTPS:    false,
	}

	// Test list files
	result, err := ListFiles(*testConfig, "")
	assert.NoError(s.T(), err, "failed when it shouldn't")
	assert.Equal(s.T(), len(result), 2)

	// Test list files with prefix
	result, err = ListFiles(*testConfig, filepath.Base(s.testFile1.Name()))
	assert.NoError(s.T(), err, "failed when it shouldn't")
	assert.Equal(s.T(), len(result), 1)

	// Test list pagination.
	// The used gofakeS3 version utilizes the continuationToken for paging.
	// Therefore, here we also implicitely test that the ListFiles function
	// reverts to using ListObjectsV2 when ListObjects paging fails.
	testConfig.MaxS3Keys = 1
	result, err = ListFiles(*testConfig, "")
	assert.NoError(s.T(), err, "failed when it shouldn't")
	assert.Equal(s.T(), len(result), 2, "list pagination failed: expected 2 files, got %v", len(result))

	// Test list failure
	testConfig.AccessKey = "wrong"
	_, err = ListFiles(*testConfig, "")
	assert.ErrorContains(s.T(), err, "failed to list objects")
}
