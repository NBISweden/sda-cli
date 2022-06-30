package upload

import (
	"io/ioutil"
	"os"
	"testing"

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

	_, err := loadConfigFile(configPath)
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

	_, err = loadConfigFile(configPath.Name())
	assert.EqualError(suite.T(), err, "key-value delimiter not found: guess_mime_type!True\n")
}

func (suite *TestSuite) TestConfigMissingCredentials() {

	configPath, err := ioutil.TempFile(os.TempDir(), "s3cmd-")
	if err != nil {
		log.Fatal(err)
	}

	defer os.Remove(configPath.Name())

	_, err = loadConfigFile(configPath.Name())
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

	_, err = loadConfigFile(configPath.Name())
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

	_, err = loadConfigFile(configPath.Name())
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
	config, _ := loadConfigFile(configPath.Name())
	var files []string

	err = uploadFiles(files, files, "", config)
	assert.EqualError(suite.T(), err, "no files to upload")
}

func (suite *TestSuite) TestTokenExpiration() {
	// Token without exp claim
	// #nosec G101
	token := "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxNzA3NDgzOTQ0IiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.7r3JJptaxQpuN0I6JwEdfIchf7OOXu--OMFprfMtwzXl2UpmjGVeGy0LWhuzG4LljA2uAp5SPrWzz_U5YKcjuw"
	expiring, err := checkTokenExpiration(token)
	assert.EqualError(suite.T(), err, "could not parse token, reason: no expiration date")
	assert.False(suite.T(), expiring)

	// Token with expired date
	// #nosec G101
	token = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxNzA3NDgzOTQ0IiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMiwiZXhwIjoxNTE2MjM5MDIyfQ.bjYdbKzzR7jbZpLgm_bCqOr_wuaO8KSCEdVJpKEh1pdJ-7klsHdOwCQoBxbmdVPIVHE0jfEEzc9IvtztTeejmg"
	expiring, err = checkTokenExpiration(token)
	assert.NoError(suite.T(), err)
	assert.True(suite.T(), expiring)

	// Token with valid expiration
	// #nosec G101
	token = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxNzA3NDgzOTQ0IiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMiwiZXhwIjoxNzA3NDgzOTQ0fQ.D7hrpd3ROXp53NnXa0PL9js2Oi1KqpKpkVMic1B23X84ksX9kbbtn4Ad4BkhO8Tm35a5hBu95CGgw5b06sd3LQ"
	expiring, err = checkTokenExpiration(token)
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
	assert.Nil(suite.T(), err)

	// Input is invalid
	_, _, err = createFilePaths("nonexistent")
	assert.ErrorContains(suite.T(), err, "no such file or directory")
}
