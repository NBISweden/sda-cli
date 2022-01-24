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

	err = ioutil.WriteFile(configPath.Name(), []byte(confFile), 0644)
	if err != nil {
		log.Fatalf("failed to write temp config file, %v", err)
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

	err = ioutil.WriteFile(configPath.Name(), []byte(confFile), 0644)
	if err != nil {
		log.Fatalf("failed to write temp config file, %v", err)
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

	err = ioutil.WriteFile(configPath.Name(), []byte(confFile), 0644)
	if err != nil {
		log.Fatalf("failed to write temp config file, %v", err)
	}

	_, err = loadConfigFile(configPath.Name())
	assert.NoError(suite.T(), err)
}

func (suite *TestSuite) TestSampleNoFiles() {

	os.Args = []string{"upload", "-config", "upload/s3cmd.conf"}

	err := Upload(os.Args)
	assert.EqualError(suite.T(), err, "no files to upload")
}
