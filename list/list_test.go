package list

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/NBISweden/sda-cli/upload"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
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

func (suite *TestSuite) TestNoConfig() {

	os.Args = []string{"list", "-config", ""}

	err := List(os.Args)
	assert.EqualError(suite.T(), err, "failed to find an s3 configuration file for listing data")
}

func (suite *TestSuite) TestTooManyArgs() {

	os.Args = []string{"list", "arg1", "arg2"}

	err := List(os.Args)
	assert.EqualError(suite.T(), err, "failed to parse prefix, only one is allowed")
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
		log.Println(err.Error())

		return
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

	// Create config file
	configPath, err := ioutil.TempFile(os.TempDir(), "s3cmd.conf")
	if err != nil {
		log.Panic(err)
	}
	defer os.Remove(configPath.Name())

	// Write config file
	err = ioutil.WriteFile(configPath.Name(), []byte(confFile), 0600)
	if err != nil {
		log.Printf("failed to write temp config file, %v", err)
	}

	// Create dir for storing file
	// The folder is not temp since list expects a prefix (bucket in s3proxy)
	// and doesn't work with the random name of the temp var
	dir := "dummy"
	err = os.Mkdir(dir, 0755)
	if err != nil {
		log.Panic(err)
	}
	defer os.RemoveAll(dir)

	// Create test file to upload
	testfile, err := ioutil.TempFile(dir, "dummy")
	if err != nil {
		log.Panic(err)
	}
	defer os.Remove(testfile.Name())

	var uploadOutput bytes.Buffer
	log.SetOutput(&uploadOutput)

	// Upload a file
	os.Args = []string{"upload", "-config", configPath.Name(), "-r", dir}
	err = upload.Upload(os.Args)
	assert.NoError(suite.T(), err)

	// Check logs that file was uploaded
	logMsg := fmt.Sprintf("%v", strings.TrimSuffix(uploadOutput.String(), "\n"))
	msg := "file uploaded"
	assert.Contains(suite.T(), logMsg, msg)

	log.SetOutput(os.Stdout)

	var listOutput bytes.Buffer
	log.SetOutput(&listOutput)
	defer log.SetOutput(os.Stdout)

	os.Args = []string{"list", "-config", configPath.Name()}
	err = List(os.Args)
	assert.NoError(suite.T(), err)

	logMsg1 := fmt.Sprintf("%v", strings.TrimSuffix(listOutput.String(), "\n"))
	msg1 := fmt.Sprintf("%v", filepath.Base(testfile.Name()))
	assert.Contains(suite.T(), logMsg1, msg1)

}
