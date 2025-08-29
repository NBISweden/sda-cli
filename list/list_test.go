package list

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"io"
	"net/http/httptest"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/feature/s3/manager"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/golang-jwt/jwt"
	"github.com/johannesboyne/gofakes3"
	"github.com/johannesboyne/gofakes3/backend/s3mem"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type ListTestSuite struct {
	suite.Suite

	tempDir      string
	configPath   string
	testFilePath string

	httpTestServer *httptest.Server
}

var configFormat = `
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
`

func TestListTestSuite(t *testing.T) {
	suite.Run(t, new(ListTestSuite))
}

func (suite *ListTestSuite) SetupSuite() {
	accessToken := suite.generateDummyToken()

	suite.tempDir = suite.T().TempDir()

	// Create a fake s3 backend
	backend := s3mem.New()
	faker := gofakes3.New(backend)
	suite.httpTestServer = httptest.NewServer(faker.Server())

	awsConfig, err := config.LoadDefaultConfig(context.Background(),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider("dummy", "dummy", accessToken)),
		config.WithRegion("eu-central-1"),
		config.WithBaseEndpoint(suite.httpTestServer.URL),
	)
	if err != nil {
		suite.FailNow("failed to create aws config", err)
	}

	s3Client := s3.NewFromConfig(awsConfig, func(o *s3.Options) {
		o.UsePathStyle = true
		o.EndpointOptions.DisableHTTPS = true
	})

	// Create config file
	suite.configPath = path.Join(suite.tempDir, "s3cmd.conf")

	// Write config file
	if err = os.WriteFile(suite.configPath, []byte(fmt.Sprintf(configFormat, accessToken, suite.httpTestServer.URL)), 0600); err != nil {
		suite.FailNow("failed to write to s3cmd.conf test file", err)
	}

	// Create bucket named dummy
	cparams := &s3.CreateBucketInput{
		Bucket: aws.String("dummy"),
	}
	_, err = s3Client.CreateBucket(context.Background(), cparams)
	if err != nil {
		suite.FailNow("failed to create s3 bucket", err)
	}

	fileToUpload := strings.NewReader("test content")

	uploader := manager.NewUploader(s3Client)

	suite.testFilePath = "dummy/testfile"

	// Upload the file to S3.
	if _, err := uploader.Upload(context.Background(), &s3.PutObjectInput{
		Body:            fileToUpload,
		Bucket:          aws.String("dummy"),
		Key:             aws.String(suite.testFilePath),
		ContentEncoding: aws.String("UTF-8"),
	}); err != nil {
		suite.FailNow("failed to upload test file", err)
	}
}
func (suite *ListTestSuite) TearDownSuite() {
	suite.httpTestServer.Close()
}

func (suite *ListTestSuite) TestListNoConfig() {
	err := List([]string{"list"}, "")
	assert.EqualError(suite.T(), err, "failed to load config file, reason: failed to read the configuration file")
}

func (suite *ListTestSuite) TestListFiles() {

	rescueStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	rescueStderr := os.Stderr
	errR, errW, _ := os.Pipe()
	os.Stderr = errW

	err := List([]string{"list"}, suite.configPath)
	assert.NoError(suite.T(), err)

	_ = w.Close()
	os.Stdout = rescueStdout
	listOutput, _ := io.ReadAll(r)
	_ = r.Close()
	assert.Contains(suite.T(), string(listOutput), fmt.Sprintf("%v", filepath.Base(suite.testFilePath)))

	// Check that host_base is in the error output, not in the stdout
	expectedHostBase := fmt.Sprintf("Remote server (host_base): %s", suite.httpTestServer.URL)
	assert.NotContains(suite.T(), string(listOutput), expectedHostBase)

	_ = errW.Close()
	os.Stderr = rescueStderr
	listError, _ := io.ReadAll(errR)
	_ = errR.Close()

	assert.Contains(suite.T(), string(listError), expectedHostBase)
}

func (suite *ListTestSuite) generateDummyToken() string {
	// Generate a new private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		suite.FailNow("failed to generate key", err)
	}

	// Create the Claims
	claims := &jwt.StandardClaims{
		Issuer:    "test",
		ExpiresAt: time.Now().Add(time.Minute * 2).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	ss, err := token.SignedString(privateKey)
	if err != nil {
		suite.FailNow("failed to sign token", err)
	}

	return ss
}
