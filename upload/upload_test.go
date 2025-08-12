package upload

import (
	"bytes"
	"fmt"
	"io"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/NBISweden/sda-cli/helpers"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/johannesboyne/gofakes3"
	"github.com/johannesboyne/gofakes3/backend/s3mem"
	"github.com/neicnordic/crypt4gh/keys"
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
	os.Setenv("ACCESSTOKEN", "") //nolint:errcheck
	*accessToken = ""
	suite.accessToken = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImtleXN0b3JlLUNIQU5HRS1NRSJ9.eyJqdGkiOiJWTWpfNjhhcEMxR2FJbXRZdFExQ0ciLCJzdWIiOiJkdW1teSIsImlzcyI6Imh0dHA6Ly9vaWRjOjkwOTAiLCJpYXQiOjE3MDc3NjMyODksImV4cCI6MTg2NTU0NzkxOSwic2NvcGUiOiJvcGVuaWQgZ2E0Z2hfcGFzc3BvcnRfdjEgcHJvZmlsZSBlbWFpbCIsImF1ZCI6IlhDNTZFTDExeHgifQ.ZFfIAOGeM2I5cvqr1qJV74qU65appYjpNJVWevGHjGA5Xk_qoRMFJXmG6AiQnYdMKnJ58sYGNjWgs2_RGyw5NyM3-pgP7EKHdWU4PrDOU84Kosg4IPMSFxbBRAEjR5X04YX_CLYW2MFk_OyM9TIln522_JBVT_jA5WTTHSmBRHntVArYYHvQdF-oFRiqL8JXWlsUBh3tqQ33sZdqd9g64YhTk9a5lEC42gn5Hg9Hm_qvkl5orzEqIg7x9z5706IBE4Zypco5ohrAKsEbA8EKbEBb0jigGgCslQNde2owUyKIkvZYmxHA78X5xpymMp9K--PgbkyMS9GtA-YwOHPs-w"
}

func (suite *TestSuite) TestSampleNoFiles() {
	confFile := fmt.Sprintf(`
	access_token = %[1]s
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
	`, suite.accessToken)

	configPath, err := os.CreateTemp(os.TempDir(), "s3cmd.conf")
	if err != nil {
		log.Fatal(err)
	}

	defer os.Remove(configPath.Name()) //nolint:errcheck

	err = os.WriteFile(configPath.Name(), []byte(confFile), 0600)
	if err != nil {
		log.Printf("failed to write temp config file, %v", err)
	}

	// Test Upload function
	os.Args = []string{"upload"}

	assert.EqualError(suite.T(), Upload(os.Args, configPath.Name()), "no files to upload")

	// Test handling of mistakenly passing a filename as an upload folder
	os.Args = []string{"upload", "-targetDir", configPath.Name()}
	assert.EqualError(suite.T(), Upload(os.Args, configPath.Name()), configPath.Name()+" is not a valid target directory")

	// Test handling of mistakenly passing a flag as an upload folder
	os.Args = []string{"upload", "-targetDir", "-r"}
	assert.EqualError(suite.T(), Upload(os.Args, configPath.Name()), "-r"+" is not a valid target directory")

	// Test passing flags at the end as well

	msg := "stat somefileOrfolder: no such file or directory"
	if runtime.GOOS == "windows" {
		msg = "CreateFile somefileOrfolder: The system cannot find the file specified."
	}
	os.Args = []string{"upload", "-r", "somefileOrfolder", "-targetDir", "somedir"}
	assert.EqualError(suite.T(), Upload(os.Args, configPath.Name()), msg)

	os.Args = []string{"upload", "somefiles", "-targetDir"}
	assert.EqualError(suite.T(), Upload(os.Args, configPath.Name()), "no files to upload")

	// Test uploadFiles function
	config, _ := helpers.LoadConfigFile(configPath.Name())
	var files []string

	err = uploadFiles(files, files, "", config)
	assert.EqualError(suite.T(), err, "no files to upload")
}

func (suite *TestSuite) TestcreateFilePaths() {
	// Create temp dir with file
	dir, err := os.MkdirTemp(os.TempDir(), "test")
	if err != nil {
		log.Panic(err)
	}
	defer os.RemoveAll(dir) //nolint:errcheck

	testfile, err := os.CreateTemp(dir, "testfile")
	if err != nil {
		log.Panic(err)
	}
	defer os.Remove(testfile.Name()) //nolint:errcheck

	// Input is a file
	_, _, err = createFilePaths(testfile.Name())
	assert.ErrorContains(suite.T(), err, "is not a directory")

	// Input is a directory
	_, out, err := createFilePaths(dir)
	assert.NoError(suite.T(), err)
	expect := testfile.Name()
	if runtime.GOOS == "windows" {
		expect = fmt.Sprint(os.TempDir() + "/" + filepath.Base(dir) + "/" + filepath.Base(testfile.Name()))
	}
	assert.Equal(suite.T(), expect, fmt.Sprint(os.TempDir()+"/"+out[0]))

	// Input is invalid
	msg := "no such file or directory"
	if runtime.GOOS == "windows" {
		msg = "The system cannot find the file specified."
	}
	_, _, err = createFilePaths("nonexistent")
	assert.ErrorContains(suite.T(), err, msg)
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

	configPath, err := os.CreateTemp(os.TempDir(), "s3cmd.conf")
	if err != nil {
		log.Panic(err)
	}
	defer os.Remove(configPath.Name()) //nolint:errcheck

	err = os.WriteFile(configPath.Name(), []byte(confFile), 0600)
	if err != nil {
		log.Printf("failed to write temp config file, %v", err)
	}

	// Create temp dir with file
	dir, err := os.MkdirTemp(os.TempDir(), "test")
	if err != nil {
		log.Panic(err)
	}
	defer os.RemoveAll(dir) //nolint:errcheck

	testfile, err := os.CreateTemp(dir, "testfile")
	if err != nil {
		log.Panic(err)
	}
	err = os.WriteFile(testfile.Name(), []byte("content"), 0600)
	if err != nil {
		log.Printf("failed to write temp config file, %v", err)
	}
	defer os.Remove(testfile.Name()) //nolint:errcheck

	var str bytes.Buffer
	log.SetOutput(&str)

	// Test recursive upload
	os.Args = []string{"upload", "--force-unencrypted", "-r", dir}
	assert.NoError(suite.T(), Upload(os.Args, configPath.Name()))

	// Check logs that file was uploaded
	logMsg := strings.ReplaceAll(fmt.Sprintf("%v", strings.TrimSuffix(str.String(), "\n")), "\\\\", "\\")
	msg := fmt.Sprintf("file uploaded to %s/dummy/%s/%s", ts.URL, filepath.Base(dir), filepath.Base(testfile.Name()))
	assert.Contains(suite.T(), logMsg, msg)

	// Check in the logs for a warning that the file was unencrypted
	warnMsg := fmt.Sprintf("input file %s is not encrypted", filepath.Clean(testfile.Name()))
	assert.Contains(suite.T(), logMsg, warnMsg)

	// Check that file showed up in the s3 bucket correctly
	result, err := s3Client.ListObjects(&s3.ListObjectsInput{
		Bucket: aws.String("dummy"),
	})
	if err != nil {
		log.Panic(err.Error())
	}
	assert.Equal(suite.T(), aws.StringValue(result.Contents[0].Key), fmt.Sprintf("%s/%s", filepath.Base(dir), filepath.Base(testfile.Name())))

	// Test upload to a different folder
	targetPath := filepath.Join("a", "b", "c")
	os.Args = []string{"upload", "--force-unencrypted", testfile.Name(), "-targetDir", targetPath}
	assert.NoError(suite.T(), Upload(os.Args, configPath.Name()))
	// Check logs that file was uploaded
	logMsg = fmt.Sprintf("%v", strings.TrimSuffix(str.String(), "\n"))
	msg = fmt.Sprintf("file uploaded to %s/dummy/%s/%s", ts.URL, filepath.ToSlash(targetPath), filepath.Base(testfile.Name()))
	assert.Contains(suite.T(), logMsg, msg)

	// Check that file showed up in the s3 bucket correctly
	result, err = s3Client.ListObjects(&s3.ListObjectsInput{
		Bucket: aws.String("dummy"),
	})
	if err != nil {
		log.Panic(err.Error())
	}
	assert.Equal(suite.T(), aws.StringValue(result.Contents[0].Key), fmt.Sprintf("%s/%s", filepath.ToSlash(targetPath), filepath.Base(testfile.Name())))

	// Test encrypt-with-key on upload.
	// Tests specific to encrypt module are not repeated here.

	// Generate a crypt4gh pub key
	pubKeyData, _, err := keys.GenerateKeyPair()
	if err != nil {
		log.Panic("Couldn't generate key pair", err)
	}

	// Write the keys to temporary files
	publicKey, err := os.CreateTemp(dir, "pubkey-")
	if err != nil {
		log.Panic("Cannot create temporary public key file", err)
	}

	if err = keys.WriteCrypt4GHX25519PublicKey(publicKey, pubKeyData); err != nil {
		log.Panicf("failed to write temporary public key file, %v", err)
	}

	// Empty buffer logs
	str.Reset()
	newArgs := []string{"upload", "--force-unencrypted", "--encrypt-with-key", publicKey.Name(), testfile.Name(), "-targetDir", "someDir"}
	assert.NoError(suite.T(), Upload(newArgs, configPath.Name()))

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

	rescueStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	rescueStderr := os.Stderr
	errR, errW, _ := os.Pipe()
	os.Stderr = errW

	os.Args = []string{"upload", "--force-unencrypted", "-r", dir}
	_ = Upload(os.Args, configPath.Name())

	w.Close()    //nolint:errcheck
	errW.Close() //nolint:errcheck
	os.Stdout = rescueStdout
	os.Stderr = rescueStderr
	uploadOutput, _ := io.ReadAll(r)
	uploadError, _ := io.ReadAll(errR)

	// check if the host_base is in the output

	expectedHostBase := "Remote server (host_base): " + strings.TrimPrefix(ts.URL, "http://")
	assert.NotContains(suite.T(), string(uploadOutput), expectedHostBase)
	assert.Contains(suite.T(), string(uploadError), expectedHostBase)

	// Check that trying to encrypt already encrypted files returns error and aborts
	encFile, err := os.CreateTemp(dir, "encFile")
	if err != nil {
		log.Panic(err)
	}
	err = os.WriteFile(encFile.Name(), []byte("crypt4gh"), 0600)
	if err != nil {
		log.Printf("failed to write temp config file, %v", err)
	}
	defer os.Remove(testfile.Name()) //nolint:errcheck
	newArgs = []string{"upload", "--encrypt-with-key", publicKey.Name(), encFile.Name()}
	assert.ErrorContains(suite.T(), Upload(newArgs, configPath.Name()), "is already encrypted")

	// Check handling of passing source files as pub key
	// (code checks first for errors related with file args)
	newArgs = []string{"upload", "--encrypt-with-key", testfile.Name()}
	assert.EqualError(suite.T(), Upload(newArgs, configPath.Name()), "no files to upload")

	// config file without an access_token
	var confFileNoToken = fmt.Sprintf(`
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

	err = os.WriteFile(configPath.Name(), []byte(confFileNoToken), 0600)
	if err != nil {
		suite.FailNow("failed to write temp config file, %v", err)
	}

	// Check that an access token is supplied
	newArgs = []string{"upload", testfile.Name()}
	assert.EqualError(suite.T(), Upload(newArgs, configPath.Name()), "no access token supplied")

	_ = os.Setenv("ACCESSTOKEN", "BadToken")
	// Supplying an accesstoken as a ENV overrules the one in the config file
	newArgs = []string{"upload", testfile.Name()}
	assert.EqualError(suite.T(), Upload(newArgs, configPath.Name()), "could not parse token, reason: token contains an invalid number of segments")

	suite.SetupTest()
	_ = os.Setenv("ACCESSTOKEN", suite.accessToken)
	newArgs = []string{"upload", testfile.Name()}
	assert.NoError(suite.T(), Upload(newArgs, configPath.Name()))

	// Supplying an accesstoken as a parameter overrules the one in the config file
	newArgs = []string{"upload", "-accessToken", "BadToken", testfile.Name()}
	assert.EqualError(suite.T(), Upload(newArgs, configPath.Name()), "could not parse token, reason: token contains an invalid number of segments")

	newArgs = []string{"upload", "-accessToken", suite.accessToken, testfile.Name()}
	assert.NoError(suite.T(), Upload(newArgs, configPath.Name()))

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

	log.SetOutput(os.Stdout)
}

func (suite *TestSuite) TestRecursiveToDifferentTarget() {
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
		log.Print(err.Error())
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

	configPath, err := os.CreateTemp(os.TempDir(), "s3cmd.conf")
	if err != nil {
		log.Print(err.Error())
	}
	defer os.Remove(configPath.Name()) //nolint:errcheck

	err = os.WriteFile(configPath.Name(), []byte(confFile), 0600)
	if err != nil {
		log.Printf("failed to write temp config file, %v", err)
	}

	// Create temp dir with file
	dir, err := os.MkdirTemp(os.TempDir(), "test")
	if err != nil {
		log.Println(err)
	}
	defer os.RemoveAll(dir) //nolint:errcheck

	testfile, err := os.CreateTemp(dir, "testfile")
	if err != nil {
		log.Println(err)
	}
	err = os.WriteFile(testfile.Name(), []byte("content"), 0600)
	if err != nil {
		log.Printf("failed to write temp config file, %v", err)
	}
	defer os.Remove(testfile.Name()) //nolint:errcheck

	var str bytes.Buffer
	log.SetOutput(&str)
	// Test recursive upload to a different folder
	targetPath := filepath.Join("a", "b", "c")
	os.Args = []string{"upload", "--force-unencrypted", "-r", dir, "-targetDir", targetPath}
	assert.NoError(suite.T(), Upload(os.Args, configPath.Name()))
	// Check logs that file was uploaded
	logMsg := fmt.Sprintf("%v", strings.TrimSuffix(str.String(), "\n"))
	msg := fmt.Sprintf("file uploaded to %s/dummy/%s", ts.URL, filepath.ToSlash(filepath.Join(targetPath, filepath.Base(dir), filepath.Base(testfile.Name()))))
	assert.Contains(suite.T(), logMsg, msg)

	// Check that file showed up in the s3 bucket correctly
	result, err := s3Client.ListObjects(&s3.ListObjectsInput{
		Bucket: aws.String("dummy"),
	})
	if err != nil {
		log.Print(err.Error())
	}
	assert.Equal(suite.T(), filepath.ToSlash(filepath.Join(targetPath, filepath.Base(dir), filepath.Base(testfile.Name()))), aws.StringValue(result.Contents[0].Key))

	log.SetOutput(os.Stdout)
}

func (suite *TestSuite) TestUploadInvalidCharacters() {
	// Create a fake s3 backend
	backend := s3mem.New()
	faker := gofakes3.New(backend)
	ts := httptest.NewServer(faker.Server())
	defer ts.Close()

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

	configPath, err := os.CreateTemp(os.TempDir(), "s3cmd.conf")
	if err != nil {
		log.Panic(err)
	}
	defer os.Remove(configPath.Name()) //nolint:errcheck

	err = os.WriteFile(configPath.Name(), []byte(confFile), 0600)
	if err != nil {
		log.Panic(err)
	}

	// Create temp dir with file
	dir, err := os.MkdirTemp(os.TempDir(), "test")
	if err != nil {
		log.Panic(err)
	}
	defer os.RemoveAll(dir) //nolint:errcheck

	// Create a test file
	testfilepath := "testfile"
	var testfile *os.File
	testfile, err = os.Create(filepath.Join(dir, testfilepath))
	if err != nil {
		log.Panic(err)
	}
	err = os.WriteFile(testfile.Name(), []byte("content"), 0600)
	if err != nil {
		log.Panic(err)
	}
	defer os.Remove(testfile.Name()) //nolint:errcheck

	// Check that target dir names with invalid characters will not be accepted
	badchars := ":*?"
	// backlash is only allowed on windows
	if runtime.GOOS != "windows" {
		badchars += "\\"
	}
	for _, badc := range badchars {
		badchar := string(badc)
		targetDir := "test" + badchar + "dir"
		os.Args = []string{"upload", "--force-unencrypted", "-targetDir", targetDir, "-r", testfile.Name()}
		err = Upload(os.Args, configPath.Name())
		assert.Error(suite.T(), err)
		assert.Equal(suite.T(), targetDir+" is not a valid target directory", err.Error())
	}

	// Filenames with :\?* can not be created on windows, skip the following tests
	if runtime.GOOS == "windows" {
		suite.T().Skip("Skipping. Cannot create filenames with invalid characters on windows")
	}

	// Test that no files with invalid characters can be uploaded
	for _, badc := range "\\:*?" {
		badchar := string(badc)
		testfilepath := "test" + badchar + "file"
		var testfile *os.File
		testfile, err := os.Create(filepath.Join(dir, testfilepath))
		if err != nil {
			log.Panic(err)
		}
		err = os.WriteFile(testfile.Name(), []byte("content"), 0600)
		if err != nil {
			log.Panic(err)
		}
		defer os.Remove(testfile.Name()) //nolint:errcheck

		os.Args = []string{"upload", "--force-unencrypted", "-r", testfile.Name()}
		err = Upload(os.Args, configPath.Name())
		assert.Error(suite.T(), err)
		assert.Equal(suite.T(), fmt.Sprintf("filepath %v contains disallowed characters: %+v", testfilepath, badchar), err.Error())
	}
}
