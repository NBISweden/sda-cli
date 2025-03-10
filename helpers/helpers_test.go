package helpers

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"io"
	"log"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
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
func generateDummyToken(expDate int64) string {
	// Generate a new private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("Failed to generate private key: %s", err)
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
		log.Fatalf("Failed to sign token: %s", err)
	}

	return ss
}

func TestHelpersTestSuite(t *testing.T) {
	suite.Run(t, new(HelperTests))
}

func (suite *HelperTests) SetupTest() {

	var err error

	// Create a temporary directory for our files
	suite.tempDir, err = os.MkdirTemp(os.TempDir(), "sda-cli-test-")
	if err != nil {
		log.Fatal("Couldn't create temporary test directory", err)
	}

	// create an existing test file with some known content
	suite.testFile, err = os.CreateTemp(suite.tempDir, "testfile-")
	if err != nil {
		log.Fatal("cannot create temporary file", err)
	}

	err = os.WriteFile(suite.testFile.Name(), []byte("content"), 0600)
	if err != nil {
		log.Fatalf("failed to write to testfile: %s", err)
	}

	// create another existing test file with some known content
	suite.testFile1, err = os.CreateTemp(suite.tempDir, "testfile-")
	if err != nil {
		log.Fatal("cannot create temporary file", err)
	}

	err = os.WriteFile(suite.testFile1.Name(), []byte("more content"), 0600)
	if err != nil {
		log.Fatalf("failed to write to testfile1: %s", err)
	}

	suite.accessToken = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImtleXN0b3JlLUNIQU5HRS1NRSJ9.eyJqdGkiOiJWTWpfNjhhcEMxR2FJbXRZdFExQ0ciLCJzdWIiOiJkdW1teSIsImlzcyI6Imh0dHA6Ly9vaWRjOjkwOTAiLCJpYXQiOjE3MDc3NjMyODksImV4cCI6MTg2NTU0NzkxOSwic2NvcGUiOiJvcGVuaWQgZ2E0Z2hfcGFzc3BvcnRfdjEgcHJvZmlsZSBlbWFpbCIsImF1ZCI6IlhDNTZFTDExeHgifQ.ZFfIAOGeM2I5cvqr1qJV74qU65appYjpNJVWevGHjGA5Xk_qoRMFJXmG6AiQnYdMKnJ58sYGNjWgs2_RGyw5NyM3-pgP7EKHdWU4PrDOU84Kosg4IPMSFxbBRAEjR5X04YX_CLYW2MFk_OyM9TIln522_JBVT_jA5WTTHSmBRHntVArYYHvQdF-oFRiqL8JXWlsUBh3tqQ33sZdqd9g64YhTk9a5lEC42gn5Hg9Hm_qvkl5orzEqIg7x9z5706IBE4Zypco5ohrAKsEbA8EKbEBb0jigGgCslQNde2owUyKIkvZYmxHA78X5xpymMp9K--PgbkyMS9GtA-YwOHPs-w"
}

func (suite *HelperTests) TearDownTest() {
	os.Remove(suite.testFile.Name())
	os.Remove(suite.testFile1.Name())
	os.Remove(suite.tempDir)
}

func (suite *HelperTests) TestFileExists() {
	// file exists
	testExists := FileExists(suite.testFile.Name())
	suite.Equal(testExists, true)
	// file does not exists
	testMissing := FileExists("does-not-exist")
	suite.Equal(testMissing, false)
	// file is a directory
	testIsDir := FileExists(suite.tempDir)
	suite.Equal(testIsDir, true)
}

func (suite *HelperTests) TestFileIsReadable() {
	// file doesn't exist
	testMissing := FileIsReadable("does-not-exist")
	suite.Equal(testMissing, false)

	// file is a directory
	testIsDir := FileIsReadable(suite.tempDir)
	suite.Equal(testIsDir, false)

	// file can be read
	testFileOk := FileIsReadable(suite.testFile.Name())
	suite.Equal(testFileOk, true)

	// test file permissions. This doesn't work on windows, so we do an extra
	// check to see if this test makes sense.
	if runtime.GOOS != "windows" {
		err := os.Chmod(suite.testFile.Name(), 0000)
		if err != nil {
			log.Fatal("Couldn't set file permissions of test file")
		}
		// file permissions don't allow reading
		testDisallowed := FileIsReadable(suite.testFile.Name())
		suite.Equal(testDisallowed, false)

		// restore permissions
		err = os.Chmod(suite.testFile.Name(), 0600)
		if err != nil {
			log.Fatal("Couldn't restore file permissions of test file")
		}
	}
}

func (suite *HelperTests) TestFormatSubcommandUsage() {
	// check formatting of malformed usage strings without %s for os.Args[0]
	malformedNoFormatString := "USAGE: do that stuff"
	testMissingArgsFormat := FormatSubcommandUsage(malformedNoFormatString)
	suite.Equal(malformedNoFormatString, testMissingArgsFormat)

	// check formatting when the USAGE string is missing
	malformedNoUsage := `module: this module does all the fancies stuff,
								   and virtually none of the non-fancy stuff.
								   run with: %s module`
	testNoUsage := FormatSubcommandUsage(malformedNoUsage)
	suite.Equal(fmt.Sprintf(malformedNoUsage, os.Args[0]), testNoUsage)

	// check formatting when the usage string is correctly formatted

	correctUsage := `USAGE: %s module <args>

module:
    this module does all the fancies stuff,
    and virtually none of the non-fancy stuff.`

	correctFormat := fmt.Sprintf(`
module:
    this module does all the fancies stuff,
    and virtually none of the non-fancy stuff.

    USAGE: %s module <args>

`, os.Args[0])
	testCorrect := FormatSubcommandUsage(correctUsage)
	suite.Equal(correctFormat, testCorrect)

}

func (suite *HelperTests) TestParseS3ErrorResponse() {
	// check bad response body by creating and passing
	// a dummy faulty io.Reader
	f, _ := os.Open(`doesn't exist`)
	defer f.Close()
	msg, err := ParseS3ErrorResponse(f)
	suite.Equal("", msg)
	suite.ErrorContains(err, "failed to read from response body")

	// check not xml
	payload := strings.NewReader("some non xml text")
	msg, err = ParseS3ErrorResponse(payload)
	suite.Equal("", msg)
	suite.EqualError(err, "cannot parse response body, reason: not xml")

	// check with malformed xml
	payload.Reset("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<Error><ed</Code><Message>All access to this bucket has been disabled.</Message><Resource>/minio/test/dummy/data_file1.c4gh</Resource><RequestId></RequestId><HostId>73e4c710-46e8-4846-b70b-86ee905a3ab0</HostId></Error>")
	msg, err = ParseS3ErrorResponse(payload)
	suite.Equal("", msg)
	suite.ErrorContains(err, "failed to unmarshal xml response")

	// check with good xml
	payload.Reset("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<Error><Code>AllAccessDisabled</Code><Message>All access to this bucket has been disabled.</Message><Resource>/minio/test/dummy/data_file1.c4gh</Resource><RequestId></RequestId><HostId>73e4c710-46e8-4846-b70b-86ee905a3ab0</HostId></Error>")
	msg, err = ParseS3ErrorResponse(payload)
	suite.Equal("{Code:AllAccessDisabled Message:All access to this bucket has been disabled. Resource:/minio/test/dummy/data_file1.c4gh}", msg)
	suite.NoError(err)
}

func (suite *HelperTests) TestConfigNoFile() {
	msg := "open nofile.conf: no such file or directory"
	if runtime.GOOS == "windows" {
		msg = "open nofile.conf: The system cannot find the file specified."
	}
	configPath := "nofile.conf"

	_, err := LoadConfigFile(configPath)
	assert.EqualError(suite.T(), err, msg)
}

func (suite *HelperTests) TestConfigWrongFile() {
	var confFile = `
access_token = someToken
access_key = someUser
host_bucket = someHostBase
guess_mime_type!True
encrypt = False
`

	configPath, err := os.CreateTemp(os.TempDir(), "s3cmd-")
	if err != nil {
		log.Fatal(err)
	}

	defer os.Remove(configPath.Name())

	err = os.WriteFile(configPath.Name(), []byte(confFile), 0600)
	if err != nil {
		log.Printf("failed to write temp config file, %v", err)
	}

	_, err = LoadConfigFile(configPath.Name())
	assert.EqualError(suite.T(), err, "key-value delimiter not found: guess_mime_type!True\n")
}

func (suite *HelperTests) TestConfigS3cmdFileFormat() {
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
		log.Fatal(err)
	}

	defer os.Remove(configPath.Name())

	err = os.WriteFile(configPath.Name(), []byte(confFile), 0600)
	if err != nil {
		log.Printf("failed to write temp config file, %v", err)
	}

	_, err = LoadConfigFile(configPath.Name())
	assert.NoError(suite.T(), err)
}

func (suite *HelperTests) TestConfigMissingCredentials() {

	configPath, err := os.CreateTemp(os.TempDir(), "s3cmd-")
	if err != nil {
		log.Fatal(err)
	}

	defer os.Remove(configPath.Name())

	_, err = LoadConfigFile(configPath.Name())
	assert.EqualError(suite.T(), err, "failed to find credentials in configuration file")
}

func (suite *HelperTests) TestConfigMissingEndpoint() {
	var confFile = `
access_token = someToken
access_key = someUser
`
	configPath, err := os.CreateTemp(os.TempDir(), "s3cmd-")
	if err != nil {
		log.Fatal(err)
	}

	defer os.Remove(configPath.Name())

	if err := os.WriteFile(configPath.Name(), []byte(confFile), 0600); err != nil {
		log.Printf("failed to write temp config file, %v", err)
	}

	_, err = LoadConfigFile(configPath.Name())
	assert.EqualError(suite.T(), err, "failed to find endpoint in configuration file")
}

func (suite *HelperTests) TestConfig() {
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
		log.Fatal(err)
	}

	defer os.Remove(configPath.Name())

	err = os.WriteFile(configPath.Name(), []byte(confFile), 0600)
	if err != nil {
		log.Printf("failed to write temp config file, %v", err)
	}

	_, err = LoadConfigFile(configPath.Name())
	assert.NoError(suite.T(), err)
}

func (suite *HelperTests) TestTokenExpiration() {
	// Token without exp claim
	token := generateDummyToken(0)
	err := CheckTokenExpiration(token)
	assert.EqualError(suite.T(), err, "could not parse token, reason: no expiration date")

	// Token with expired date
	token = generateDummyToken(time.Now().Unix())
	err = CheckTokenExpiration(token)
	assert.EqualError(suite.T(), err, "the provided access token has expired, please renew it")

	// Token with valid expiration, less than 2 hours
	token = generateDummyToken(time.Now().Add(time.Hour).Unix())

	storeStderr := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w

	err = CheckTokenExpiration(token)
	assert.NoError(suite.T(), err)

	w.Close()
	out, _ := io.ReadAll(r)
	os.Stderr = storeStderr

	msg := "WARNING! The provided access token expires in only 59 minutes."
	assert.Contains(suite.T(), string(out), msg)

	// Token with valid expiration, more than a day
	exp := time.Now().Add(time.Hour * 72)
	token = generateDummyToken(exp.Unix())

	storeStderr = os.Stderr
	r, w, _ = os.Pipe()
	os.Stderr = w

	err = CheckTokenExpiration(token)
	assert.NoError(suite.T(), err)

	w.Close()
	out, _ = io.ReadAll(r)
	os.Stderr = storeStderr

	msg = "The provided access token expires on " + exp.Format(time.RFC1123)
	assert.Contains(suite.T(), string(out), msg)
}

func (suite *HelperTests) TestPubKeyEmptyField() {
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
		log.Fatal(err)
	}

	defer os.Remove(configPath.Name())

	err = os.WriteFile(configPath.Name(), []byte(confFile), 0600)
	if err != nil {
		log.Printf("failed to write temp config file, %v", err)
	}

	_, err = GetPublicKeyFromSession()
	assert.EqualError(suite.T(), err, "public key not found in the configuration")
}

func (suite *HelperTests) TestGetPublicKeyFromSession() {

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
		log.Fatal(err)
	}

	defer os.Remove(configPath.Name())

	err = os.WriteFile(configPath.Name(), []byte(confFile), 0600)
	if err != nil {
		log.Printf("failed to write temp config file, %v", err)
	}

	_, err = GetPublicKeyFromSession()
	assert.NoError(suite.T(), err)

	if assert.FileExists(suite.T(), "key-from-oidc.pub.pem") {
		os.Remove("key-from-oidc.pub.pem")
	}
}

func (suite *HelperTests) TestInvalidCharacters() {
	// Test that file paths with invalid characters trigger errors
	for _, badc := range "\x00\x7F\x1A:*?\\<>\"|!'();@&=+$,%#[]" {
		badchar := string(badc)
		testfilepath := "test" + badchar + "file"

		err := CheckValidChars(testfilepath)
		assert.Error(suite.T(), err)
		assert.Equal(suite.T(), fmt.Sprintf("filepath %v contains disallowed characters: %+v", testfilepath, badchar), err.Error())
	}
}

func (suite *HelperTests) TestCreatePubFile() {
	var pubKeyContent = `339eb2a458fec5e23aa8b57cfcb35f10e7389025816e44d4234f814ed2aeed3f`
	var expectedPubKey = `-----BEGIN CRYPT4GH PUBLIC KEY-----
MzM5ZWIyYTQ1OGZlYzVlMjNhYThiNTdjZmNiMzVmMTA=
-----END CRYPT4GH PUBLIC KEY-----
`
	_, err := CreatePubFile(pubKeyContent, os.TempDir()+"/test_public_file.pub.pem")
	assert.NoError(suite.T(), err)

	pubFile, _ := os.ReadFile(os.TempDir() + "/test_public_file.pub.pem")
	s := string(pubFile)
	assert.Equal(suite.T(), expectedPubKey, s)
	defer os.Remove(os.TempDir() + "/test_public_file.pub.pem")
}

func (suite *HelperTests) TestListFiles() {

	// Create a fake s3 backend
	backend := s3mem.New()
	faker := gofakes3.New(backend)
	ts := httptest.NewServer(faker.Server())
	defer ts.Close()

	// Configure S3 client
	s3Config := &aws.Config{
		Credentials:      credentials.NewStaticCredentials("dummy", "dummy", suite.accessToken),
		Endpoint:         aws.String(ts.URL),
		Region:           aws.String("eu-central-1"),
		DisableSSL:       aws.Bool(true),
		S3ForcePathStyle: aws.Bool(true),
	}
	newSession, _ := session.NewSession(s3Config)
	s3Client := s3.New(newSession)

	// Create bucket named dummy
	cparams := &s3.CreateBucketInput{
		Bucket: aws.String("dummy"),
	}
	_, err := s3Client.CreateBucket(cparams)
	if err != nil {
		log.Panic(err.Error())
	}

	// Upload two test files
	file, err := os.Open(suite.testFile.Name())
	if err != nil {
		log.Panic(err.Error())
	}
	defer file.Close()

	_, err = s3Client.PutObject(&s3.PutObjectInput{
		Bucket: aws.String("dummy"),
		Key:    aws.String("dummy/" + filepath.Base(suite.testFile.Name())),
		Body:   file,
	})
	if err != nil {
		log.Panic(err.Error())
	}

	file1, err := os.Open(suite.testFile1.Name())
	if err != nil {
		log.Panic(err.Error())
	}
	defer file1.Close()
	_, err = s3Client.PutObject(&s3.PutObjectInput{
		Bucket: aws.String("dummy"),
		Key:    aws.String("dummy/" + filepath.Base(suite.testFile1.Name())),
		Body:   file1,
	})
	if err != nil {
		log.Panic(err.Error())
	}

	testConfig := &Config{
		AccessToken: suite.accessToken,
		AccessKey:   "dummy",
		SecretKey:   "dummy",
		HostBase:    strings.TrimPrefix(ts.URL, "http://"),
		UseHTTPS:    false,
	}

	// Test list files
	result, err := ListFiles(*testConfig, "")
	assert.NoError(suite.T(), err, "failed when it shouldn't")
	assert.Equal(suite.T(), len(result), 2)

	// Test list files with prefix
	result, err = ListFiles(*testConfig, filepath.Base(suite.testFile1.Name()))
	assert.NoError(suite.T(), err, "failed when it shouldn't")
	assert.Equal(suite.T(), len(result), 1)

	// Test list pagination
	testConfig.MaxS3Keys = 1
	result, err = ListFiles(*testConfig, "")
	assert.NoError(suite.T(), err, "failed when it shouldn't")
	assert.Equal(suite.T(), len(result), 2, "list pagination failed: expected 2 files, got %v", len(result))

	// Test list failure
	testConfig.AccessKey = "wrong"
	_, err = ListFiles(*testConfig, "")
	assert.ErrorContains(suite.T(), err, "failed to list objects")
}
