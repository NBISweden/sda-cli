package list

import (
	"bytes"
	"fmt"
	"io"
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
	accessToken string
}

func TestConfigTestSuite(t *testing.T) {
	suite.Run(t, new(TestSuite))
}

func (suite *TestSuite) SetupTest() {
	suite.accessToken = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImtleXN0b3JlLUNIQU5HRS1NRSJ9.eyJqdGkiOiJWTWpfNjhhcEMxR2FJbXRZdFExQ0ciLCJzdWIiOiJkdW1teSIsImlzcyI6Imh0dHA6Ly9vaWRjOjkwOTAiLCJpYXQiOjE3MDc3NjMyODksImV4cCI6MTg2NTU0NzkxOSwic2NvcGUiOiJvcGVuaWQgZ2E0Z2hfcGFzc3BvcnRfdjEgcHJvZmlsZSBlbWFpbCIsImF1ZCI6IlhDNTZFTDExeHgifQ.ZFfIAOGeM2I5cvqr1qJV74qU65appYjpNJVWevGHjGA5Xk_qoRMFJXmG6AiQnYdMKnJ58sYGNjWgs2_RGyw5NyM3-pgP7EKHdWU4PrDOU84Kosg4IPMSFxbBRAEjR5X04YX_CLYW2MFk_OyM9TIln522_JBVT_jA5WTTHSmBRHntVArYYHvQdF-oFRiqL8JXWlsUBh3tqQ33sZdqd9g64YhTk9a5lEC42gn5Hg9Hm_qvkl5orzEqIg7x9z5706IBE4Zypco5ohrAKsEbA8EKbEBb0jigGgCslQNde2owUyKIkvZYmxHA78X5xpymMp9K--PgbkyMS9GtA-YwOHPs-w"
}

func (suite *TestSuite) TestNoConfig() {

	os.Args = []string{"list"}

	err := List(os.Args, "")
	assert.EqualError(suite.T(), err, "failed to load config file, reason: failed to read the configuration file")
}

func (suite *TestSuite) TestFunctionality() {

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
		log.Println(err.Error())

		return
	}

	// Create conf file for sda-cli
	var confFile = fmt.Sprintf(`
	access_token = %[1]s
	host_base = %[2]s
	encoding = UTF-8
	host_bucket = %[2]s
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
	`, suite.accessToken, strings.TrimPrefix(ts.URL, "http://"))

	// Create config file
	configPath, err := os.CreateTemp(os.TempDir(), "s3cmd.conf")
	if err != nil {
		log.Panic(err)
	}
	defer os.Remove(configPath.Name())

	// Write config file
	err = os.WriteFile(configPath.Name(), []byte(confFile), 0600)
	if err != nil {
		log.Printf("failed to write temp config file, %v", err)
	}

	// Create dir for storing file
	// The folder is not temp since list expects a prefix (bucket in s3proxy)
	// and doesn't work with the random name of the temp var
	dir := "dummy"
	err = os.Mkdir(dir, 0755)
	if err != nil {
		log.Error(err)
	}
	defer os.RemoveAll(dir)

	// Create test file to upload
	testfile, err := os.CreateTemp(dir, "dummy")
	if err != nil {
		log.Panic(err)
	}
	defer os.Remove(testfile.Name())

	var uploadOutput bytes.Buffer
	log.SetOutput(&uploadOutput)

	// Upload a file
	os.Args = []string{"upload", "--force-unencrypted", "-r", dir}
	err = upload.Upload(os.Args, configPath.Name())
	assert.NoError(suite.T(), err)

	// Check logs that file was uploaded
	logMsg := fmt.Sprintf("%v", strings.TrimSuffix(uploadOutput.String(), "\n"))
	msg := "file uploaded"
	assert.Contains(suite.T(), logMsg, msg)

	log.SetOutput(os.Stdout)

	rescueStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	rescueStderr := os.Stderr
	errR, errW, _ := os.Pipe()
	os.Stderr = errW

	os.Args = []string{"list"}
	err = List(os.Args, configPath.Name())
	assert.NoError(suite.T(), err)

	w.Close()
	os.Stdout = rescueStdout
	listOutput, _ := io.ReadAll(r)
	msg1 := fmt.Sprintf("%v", filepath.Base(testfile.Name()))
	assert.Contains(suite.T(), string(listOutput), msg1)

	errW.Close()
	os.Stderr = rescueStderr
	listError, _ := io.ReadAll(errR)

	// Check that host_base is in the error output, not in the stdout
	expectedHostBase := "Remote server (host_base): " + strings.TrimPrefix(ts.URL, "http://")
	assert.NotContains(suite.T(), string(listOutput), expectedHostBase)
	assert.Contains(suite.T(), string(listError), expectedHostBase)
}
