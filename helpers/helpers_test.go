package helpers

import (
	"fmt"
	"log"
	"os"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type HelperTests struct {
	suite.Suite
	tempDir  string
	testFile *os.File
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
		log.Fatal("cannot create temporary public key file", err)
	}

	err = os.WriteFile(suite.testFile.Name(), []byte("content"), 0600)
	if err != nil {
		log.Fatalf("failed to write to testfile: %s", err)
	}
}

func (suite *HelperTests) TearDownTest() {
	os.Remove(suite.testFile.Name())
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
	// #nosec G101
	token := "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxNzA3NDgzOTQ0IiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.7r3JJptaxQpuN0I6JwEdfIchf7OOXu--OMFprfMtwzXl2UpmjGVeGy0LWhuzG4LljA2uAp5SPrWzz_U5YKcjuw"
	expiring, err := CheckTokenExpiration(token)
	assert.EqualError(suite.T(), err, "could not parse token, reason: no expiration date")
	assert.False(suite.T(), expiring)

	// Token with expired date
	// #nosec G101
	token = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxNzA3NDgzOTQ0IiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMiwiZXhwIjoxNTE2MjM5MDIyfQ.bjYdbKzzR7jbZpLgm_bCqOr_wuaO8KSCEdVJpKEh1pdJ-7klsHdOwCQoBxbmdVPIVHE0jfEEzc9IvtztTeejmg"
	expiring, err = CheckTokenExpiration(token)
	assert.NoError(suite.T(), err)
	assert.True(suite.T(), expiring)

	// Token with valid expiration
	// #nosec G101
	token = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxNzA3NDgzOTQ0IiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMiwiZXhwIjoxNzA3NDgzOTQ0fQ.D7hrpd3ROXp53NnXa0PL9js2Oi1KqpKpkVMic1B23X84ksX9kbbtn4Ad4BkhO8Tm35a5hBu95CGgw5b06sd3LQ"
	expiring, err = CheckTokenExpiration(token)
	assert.NoError(suite.T(), err)
	assert.False(suite.T(), expiring)
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

	_, err = GetPublicKey()
	assert.EqualError(suite.T(), err, "public key not found in the configuration")
}

func (suite *HelperTests) TestGetPublicKey() {

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

	_, err = GetPublicKey()
	assert.NoError(suite.T(), err)

	if assert.FileExists(suite.T(), "key-from-oidc.pub.pem") {
		os.Remove("key-from-oidc.pub.pem")
	}
}

func (suite *HelperTests) TestInvalidCharacters() {
	// Test that file paths with invalid characters trigger errors
	for _, badc := range "\x00\x7F\x1A:*?\\" {
		badchar := string(badc)
		testfilepath := "test" + badchar + "file"

		err := CheckValidChars(testfilepath)
		assert.Error(suite.T(), err)
		assert.Equal(suite.T(), fmt.Sprintf("filepath %v contains disallowed characters: %+v", testfilepath, badchar), err.Error())
	}
}
