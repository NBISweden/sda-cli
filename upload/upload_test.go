package upload

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/elixir-oslo/crypt4gh/keys"
	"github.com/johannesboyne/gofakes3"
	"github.com/johannesboyne/gofakes3/backend/s3mem"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type TestSuite struct {
	suite.Suite
}

func TestConfigTestSuite(t *testing.T) {
	suite.Run(t, new(TestSuite))
}

func (suite *TestSuite) SetupTest() {

}

func (suite *TestSuite) TestConfigNoFile() {

	configPath := "nofile.conf"

	_, err := LoadConfigFile(configPath)
	assert.EqualError(suite.T(), err, "open nofile.conf: no such file or directory")
}

func (suite *TestSuite) TestConfigWrongFile() {
	var confFile = `
access_token = someToken
access_key = someUser
host_bucket = someHostBase
guess_mime_type!True
encrypt = False
`

	configPath, err := ioutil.TempFile(os.TempDir(), "s3cmd-")
	if err != nil {
		log.Fatal(err)
	}

	defer os.Remove(configPath.Name())

	err = ioutil.WriteFile(configPath.Name(), []byte(confFile), 0600)
	if err != nil {
		log.Printf("failed to write temp config file, %v", err)
	}

	_, err = LoadConfigFile(configPath.Name())
	assert.EqualError(suite.T(), err, "key-value delimiter not found: guess_mime_type!True\n")
}

func (suite *TestSuite) TestConfigMissingCredentials() {

	configPath, err := ioutil.TempFile(os.TempDir(), "s3cmd-")
	if err != nil {
		log.Fatal(err)
	}

	defer os.Remove(configPath.Name())

	_, err = LoadConfigFile(configPath.Name())
	assert.EqualError(suite.T(), err, "failed to find credentials in configuration file")
}

func (suite *TestSuite) TestConfigMissingEndpoint() {
	var confFile = `
access_token = someToken
access_key = someUser
`
	configPath, err := ioutil.TempFile(os.TempDir(), "s3cmd-")
	if err != nil {
		log.Fatal(err)
	}

	defer os.Remove(configPath.Name())

	err = ioutil.WriteFile(configPath.Name(), []byte(confFile), 0600)
	if err != nil {
		log.Printf("failed to write temp config file, %v", err)
	}

	_, err = LoadConfigFile(configPath.Name())
	assert.EqualError(suite.T(), err, "failed to find endpoint in configuration file")
}

func (suite *TestSuite) TestConfig() {
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
	configPath, err := ioutil.TempFile(os.TempDir(), "s3cmd-")
	if err != nil {
		log.Fatal(err)
	}

	defer os.Remove(configPath.Name())

	err = ioutil.WriteFile(configPath.Name(), []byte(confFile), 0600)
	if err != nil {
		log.Printf("failed to write temp config file, %v", err)
	}

	_, err = LoadConfigFile(configPath.Name())
	assert.NoError(suite.T(), err)
}

func (suite *TestSuite) TestSampleNoFiles() {

	var confFile = `
	access_token = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxNzA3NDgzOTQ0IiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMiwiZXhwIjoxNzA3NDgzOTQ0fQ.D7hrpd3ROXp53NnXa0PL9js2Oi1KqpKpkVMic1B23X84ksX9kbbtn4Ad4BkhO8Tm35a5hBu95CGgw5b06sd3LQ"
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
	configPath, err := ioutil.TempFile(os.TempDir(), "s3cmd.conf")
	if err != nil {
		log.Fatal(err)
	}

	defer os.Remove(configPath.Name())

	err = ioutil.WriteFile(configPath.Name(), []byte(confFile), 0600)
	if err != nil {
		log.Printf("failed to write temp config file, %v", err)
	}

	// Test Upload function
	os.Args = []string{"upload", "-config", configPath.Name()}

	err = Upload(os.Args)
	assert.EqualError(suite.T(), err, "no files to upload")

	// Test handling of mistakenly passing a filename as an upload folder
	os.Args = []string{"upload", "-config", configPath.Name(), "-targetDir", configPath.Name()}
	err = Upload(os.Args)
	assert.EqualError(suite.T(), err, configPath.Name()+" is not a valid target directory")

	// Test handling of mistakenly passing a flag as an upload folder
	os.Args = []string{"upload", "-config", configPath.Name(), "-targetDir", "-r"}
	err = Upload(os.Args)
	assert.EqualError(suite.T(), err, "-r"+" is not a valid target directory")

	// Test passing flags at the end as well
	os.Args = []string{"upload", "-config", configPath.Name(), "-r", "somefileOrfolder", "-targetDir", "somedir"}
	err = Upload(os.Args)
	assert.EqualError(suite.T(), err, "stat somefileOrfolder: no such file or directory")

	os.Args = []string{"upload", "-config", configPath.Name(), "somefiles", "-targetDir"}
	err = Upload(os.Args)
	assert.EqualError(suite.T(), err, "-config is not a valid target directory")

	// Test uploadFiles function
	config, _ := LoadConfigFile(configPath.Name())
	var files []string

	err = uploadFiles(files, files, "", config)
	assert.EqualError(suite.T(), err, "no files to upload")
}

func (suite *TestSuite) TestTokenExpiration() {
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

func (suite *TestSuite) TestcreateFilePaths() {

	// Create temp dir with file
	dir, err := ioutil.TempDir(os.TempDir(), "test")
	if err != nil {
		log.Panic(err)
	}
	defer os.RemoveAll(dir)

	testfile, err := ioutil.TempFile(dir, "testfile")
	if err != nil {
		log.Panic(err)
	}
	defer os.Remove(testfile.Name())

	// Input is a file
	_, _, err = createFilePaths(testfile.Name())
	assert.ErrorContains(suite.T(), err, "is not a directory")

	// Input is a directory
	_, _, err = createFilePaths(dir)
	assert.NoError(suite.T(), err)

	// Input is invalid
	_, _, err = createFilePaths("nonexistent")
	assert.ErrorContains(suite.T(), err, "no such file or directory")
}

func (suite *TestSuite) TestFunctionality() {

	// Create a fake s3 backend
	backend := s3mem.New()
	faker := gofakes3.New(backend)
	ts := httptest.NewServer(faker.Server())
	defer ts.Close()

	// Configure S3 client
	s3Config := &aws.Config{
		Credentials:      credentials.NewStaticCredentials("dummy", "dummy", "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxNzA3NDgzOTQ0IiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMiwiZXhwIjoxNzA3NDgzOTQ0fQ.D7hrpd3ROXp53NnXa0PL9js2Oi1KqpKpkVMic1B23X84ksX9kbbtn4Ad4BkhO8Tm35a5hBu95CGgw5b06sd3LQ"),
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

	// Create conf file for sda-cli
	var confFile = fmt.Sprintf(`
	access_token = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxNzA3NDgzOTQ0IiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMiwiZXhwIjoxNzA3NDgzOTQ0fQ.D7hrpd3ROXp53NnXa0PL9js2Oi1KqpKpkVMic1B23X84ksX9kbbtn4Ad4BkhO8Tm35a5hBu95CGgw5b06sd3LQ"
	host_base = %[1]s
	encoding = UTF-8
	host_bucket = %[1]s
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
	`, strings.TrimPrefix(ts.URL, "http://"))

	configPath, err := ioutil.TempFile(os.TempDir(), "s3cmd.conf")
	if err != nil {
		log.Panic(err)
	}
	defer os.Remove(configPath.Name())

	err = ioutil.WriteFile(configPath.Name(), []byte(confFile), 0600)
	if err != nil {
		log.Printf("failed to write temp config file, %v", err)
	}

	// Create temp dir with file
	dir, err := ioutil.TempDir(os.TempDir(), "test")
	if err != nil {
		log.Panic(err)
	}
	defer os.RemoveAll(dir)

	testfile, err := ioutil.TempFile(dir, "testfile")
	if err != nil {
		log.Panic(err)
	}
	err = ioutil.WriteFile(testfile.Name(), []byte("content"), 0600)
	if err != nil {
		log.Printf("failed to write temp config file, %v", err)
	}
	defer os.Remove(testfile.Name())

	var str bytes.Buffer
	log.SetOutput(&str)
	defer log.SetOutput(os.Stdout)

	// Test recursive upload
	os.Args = []string{"upload", "-config", configPath.Name(), "-r", dir}
	err = Upload(os.Args)
	assert.NoError(suite.T(), err)

	// Check logs that file was uploaded
	logMsg := fmt.Sprintf("%v", strings.TrimSuffix(str.String(), "\n"))
	msg := fmt.Sprintf("file uploaded to %s/dummy/%s/%s", ts.URL, filepath.Base(dir), filepath.Base(testfile.Name()))
	assert.Contains(suite.T(), logMsg, msg)

	// Check that file showed up in the s3 bucket correctly
	result, err := s3Client.ListObjects(&s3.ListObjectsInput{
		Bucket: aws.String("dummy"),
	})
	if err != nil {
		log.Panic(err.Error())
	}
	assert.Equal(suite.T(), aws.StringValue(result.Contents[0].Key), fmt.Sprintf("%s/%s", filepath.Base(dir), filepath.Base(testfile.Name())))

	// Test upload to a different folder
	os.Args = []string{"upload", "-config", configPath.Name(), testfile.Name(), "-targetDir", "a"}
	err = Upload(os.Args)
	assert.NoError(suite.T(), err)

	// Check logs that file was uploaded
	logMsg = fmt.Sprintf("%v", strings.TrimSuffix(str.String(), "\n"))
	msg = fmt.Sprintf("file uploaded to %s/dummy/a/%s", ts.URL, filepath.Base(testfile.Name()))
	assert.Contains(suite.T(), logMsg, msg)

	// Check that file showed up in the s3 bucket correctly
	result, err = s3Client.ListObjects(&s3.ListObjectsInput{
		Bucket: aws.String("dummy"),
	})
	if err != nil {
		log.Panic(err.Error())
	}
	assert.Equal(suite.T(), aws.StringValue(result.Contents[0].Key), fmt.Sprintf("a/%s", filepath.Base(testfile.Name())))

	// Test encrypt-with-key on upload.
	// Tests specific to encrypt module are not repeated here.

	// Generate a crypt4gh pub key
	pubKeyData, _, err := keys.GenerateKeyPair()
	if err != nil {
		log.Panic("Couldn't generate key pair", err)
	}

	// Write the keys to temporary files
	publicKey, err := ioutil.TempFile(dir, "pubkey-")
	if err != nil {
		log.Panic("Cannot create temporary public key file", err)
	}

	err = keys.WriteCrypt4GHX25519PublicKey(publicKey, pubKeyData)
	if err != nil {
		log.Panicf("failed to write temporary public key file, %v", err)
	}

	// Empty buffer logs
	str.Reset()
	newArgs := []string{"upload", "-config", configPath.Name(), "--encrypt-with-key", publicKey.Name(), testfile.Name(), "-targetDir", "someDir"}
	err = Upload(newArgs)
	assert.NoError(suite.T(), err)

	// Check logs that encrypted file was uploaded
	logMsg = fmt.Sprintf("%v", strings.TrimSuffix(str.String(), "\n"))
	msg = fmt.Sprintf("file uploaded to %s/dummy/someDir/%s.c4gh", ts.URL, filepath.Base(testfile.Name()))
	assert.Contains(suite.T(), logMsg, msg)

	// Check that file showed up in the s3 bucket correctly
	result, err = s3Client.ListObjects(&s3.ListObjectsInput{
		Bucket: aws.String("dummy"),
	})
	if err != nil {
		log.Panic(err.Error())
	}
	assert.Equal(suite.T(), aws.StringValue(result.Contents[1].Key), "someDir/"+filepath.Base(testfile.Name())+".c4gh")

	// Check that the respective unencrypted file was not uploaded
	msg = fmt.Sprintf("Uploading %s with", testfile.Name())
	assert.NotContains(suite.T(), logMsg, msg)

	// Check that trying to encrypt already encrypted files returns error and aborts
	newArgs = []string{"upload", "-config", configPath.Name(), "--encrypt-with-key", publicKey.Name(), dir, "-r"}
	err = Upload(newArgs)
	assert.EqualError(suite.T(), err, "aborting")

	// Check handling of passing source files as pub key
	// (code checks first for errors related with file args)
	newArgs = []string{"upload", "-config", configPath.Name(), "--encrypt-with-key", testfile.Name()}
	err = Upload(newArgs)
	assert.EqualError(suite.T(), err, "no files to upload")

	// If both a bad key and already encrypted file args are given,
	// file arg errors are captured first
	newArgs = []string{"upload", "-config", configPath.Name(), "--encrypt-with-key", "somekey", testfile.Name()}
	err = Upload(newArgs)
	assert.EqualError(suite.T(), err, "aborting")

	// Remove hash files created by Encrypt
	if err := os.Remove("checksum_encrypted.md5"); err != nil {
		log.Panic(err)
	}
	if err := os.Remove("checksum_unencrypted.md5"); err != nil {
		log.Panic(err)
	}
	if err := os.Remove("checksum_encrypted.sha256"); err != nil {
		log.Panic(err)
	}
	if err := os.Remove("checksum_unencrypted.sha256"); err != nil {
		log.Panic(err)
	}
}
