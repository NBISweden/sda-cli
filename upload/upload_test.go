package upload

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"flag"
	"fmt"
	"io"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/NBISweden/sda-cli/helpers"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/golang-jwt/jwt"
	"github.com/johannesboyne/gofakes3"
	"github.com/johannesboyne/gofakes3/backend/s3mem"
	"github.com/neicnordic/crypt4gh/keys"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type UploadTestSuite struct {
	suite.Suite
	tempDir            string
	filesToUploadDir   string // Setup test will create a sub directory under tempDir where a file will be created for upload testing such that we do not upload the s3cmd.conf and public key files
	accessToken        string
	configFilePath     string
	uploadTestFilePath string
	publicKeyFilePath  string
	s3MockHTTPServer   *httptest.Server
	s3Client           *s3.Client
}

var configFileFormat = `
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
encrypt = False`

func TestUploadTestSuite(t *testing.T) {
	suite.Run(t, new(UploadTestSuite))
}

func (s *UploadTestSuite) SetupTest() {
	// Reset flag values from any previous test invocation
	Args = flag.NewFlagSet("upload", flag.ContinueOnError)
	dirUpload = Args.Bool("r", false, "Upload directories recursively.")
	targetDir = Args.String("targetDir", "",
		"Upload files or folders into this directory.  If flag is omitted,\n"+
			"all data will be uploaded in the user's base directory.")
	forceOverwrite = Args.Bool("force-overwrite", false, "Force overwrite existing files.")
	continueUpload = Args.Bool("continue", false, "Skip existing files and continue with the rest.")
	pubKeyPath = Args.String("encrypt-with-key", "",
		"Public key file to use for encryption of files before upload.\n"+
			"The key file may optionally contain several concatenated public keys.\n"+
			"Only unencrypted data should be provided when this flag is set.",
	)
	accessToken = Args.String("accessToken", "", "Access token to the inbox service.\n(optional, if it is set in the config file or exported as the ENV `ACCESSTOKEN`)")
	_ = os.Unsetenv("ACCESSTOKEN")
	*accessToken = ""

	s.accessToken = s.generateDummyToken()
	s.tempDir = s.T().TempDir()

	// Create a fake s3 backend
	backend := s3mem.New()
	faker := gofakes3.New(backend)
	s.s3MockHTTPServer = httptest.NewServer(faker.Server())

	// Configure S3 client
	awsConfig, err := config.LoadDefaultConfig(context.TODO(),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider("dummy", "dummy", s.accessToken)),
		config.WithRegion("eu-central-1"),
		config.WithBaseEndpoint(s.s3MockHTTPServer.URL),
	)
	if err != nil {
		s.FailNow("failed to create aws config", err)
	}
	s.s3Client = s3.NewFromConfig(awsConfig, func(o *s3.Options) {
		o.UsePathStyle = true
		o.EndpointOptions.DisableHTTPS = true
	})
	// Create bucket named dummy
	cparams := &s3.CreateBucketInput{
		Bucket: aws.String("dummy"),
	}
	if _, err := s.s3Client.CreateBucket(context.TODO(), cparams); err != nil {
		s.FailNow("failed to create s3 bucket", err)
	}

	s.configFilePath = filepath.Join(s.tempDir, "s3cmd.conf")
	if err := os.WriteFile(s.configFilePath, fmt.Appendf([]byte{}, configFileFormat, s.accessToken, s.s3MockHTTPServer.URL), 0600); err != nil {
		s.FailNow("failed to write s3cmd config file")
	}
	s.filesToUploadDir, err = os.MkdirTemp(s.tempDir, "upload_files")
	if err != nil {
		s.FailNow("failed to create files to upload temp dir", err)
	}
	uploadTestFile, err := os.CreateTemp(s.filesToUploadDir, "upload_test_file")
	if err != nil {
		s.FailNow("failed to create test upload file")
	}
	if _, err := uploadTestFile.Write([]byte("test content")); err != nil {
		s.FailNow("failed to write to test upload file")
	}
	_ = uploadTestFile.Close()
	s.uploadTestFilePath = uploadTestFile.Name()

	// Generate a crypt4gh pub key
	pubKeyData, _, err := keys.GenerateKeyPair()
	if err != nil {
		s.FailNow("Couldn't generate key pair", err)
	}
	// Write the keys to temporary files
	publicKey, err := os.CreateTemp(s.tempDir, "pubkey-")
	if err != nil {
		s.FailNow("Cannot create temporary public key file", err)
	}
	if err := keys.WriteCrypt4GHX25519PublicKey(publicKey, pubKeyData); err != nil {
		s.FailNow("failed to write temporary public key file, %v", err)
	}
	_ = publicKey.Close()
	s.publicKeyFilePath = publicKey.Name()
}

func (s *UploadTestSuite) TearDownTest() {
	s.s3MockHTTPServer.Close()
	// Remove hash files created by Encrypt
	_ = os.Remove("checksum_encrypted.md5")
	_ = os.Remove("checksum_unencrypted.md5")
	_ = os.Remove("checksum_encrypted.sha256")
	_ = os.Remove("checksum_unencrypted.sha256")
}

// Test calling upload without passing any files or target dir
func (s *UploadTestSuite) TestUploadNoFiles() {
	assert.EqualError(s.T(), Upload([]string{"upload"}, s.configFilePath), "no files to upload")
}

// Test handling of mistakenly passing a filename as an upload folder
func (s *UploadTestSuite) TestUploadFileNameAsTargetDir() {
	assert.EqualError(s.T(), Upload([]string{"upload", "-targetDir", s.configFilePath}, s.configFilePath), fmt.Sprintf("%s is not a valid target directory", s.configFilePath))
}

// Test handling of mistakenly passing a flag as an upload folder
func (s *UploadTestSuite) TestUploadFlagAsTargetDir() {
	assert.EqualError(s.T(), Upload([]string{"upload", "-targetDir", "-r"}, s.configFilePath), "-r is not a valid target directory")
}

// Test passing target dir flag at the end
func (s *UploadTestSuite) TestUploadTargetDirFlagAfterFileName() {
	assert.EqualError(s.T(), Upload([]string{"upload", "-r", s.uploadTestFilePath, "-targetDir", "somedir"}, s.configFilePath), fmt.Sprintf("input file %s is not encrypted. All files must be encrypted unless using -encrypt-with-key", s.uploadTestFilePath))
}

// Test passing target dir flag at the end with out value
func (s *UploadTestSuite) TestUploadTargetDirFlagNoValueAfterFileName() {
	assert.EqualError(s.T(), Upload([]string{"upload", s.uploadTestFilePath, "-targetDir"}, s.configFilePath), fmt.Sprintf("%s is not a valid target directory", s.uploadTestFilePath))
}

// Test uploadFiles function without files
func (s *UploadTestSuite) TestUploadFilesNoFiles() {
	loadedConfig, _ := helpers.LoadConfigFile(s.configFilePath)
	assert.EqualError(s.T(), uploadFiles([]string{}, []string{}, "", loadedConfig), "no files to upload")
}

func (s *UploadTestSuite) TestCreateFilePathsFileAsInput() {
	_, _, err := createFilePaths(s.uploadTestFilePath)
	assert.ErrorContains(s.T(), err, "is not a directory")
}

func (s *UploadTestSuite) TestCreateFilePaths() {
	absolutePaths, relativePaths, err := createFilePaths(s.tempDir)
	assert.NoError(s.T(), err)

	expectedAbsolutePaths := []string{
		s.publicKeyFilePath,
		s.uploadTestFilePath,
		s.configFilePath,
	}
	s.ElementsMatch(expectedAbsolutePaths, absolutePaths)

	uploadTestFileDir, uploadTestFileName := filepath.Split(s.uploadTestFilePath)
	_, publicKeyfileName := filepath.Split(s.publicKeyFilePath)
	_, configFileName := filepath.Split(s.configFilePath)
	expectedRelativePaths := []string{
		filepath.ToSlash(filepath.Join(filepath.Base(s.tempDir), publicKeyfileName)),
		filepath.ToSlash(filepath.Join(filepath.Base(s.tempDir), filepath.Base(uploadTestFileDir), uploadTestFileName)),
		filepath.ToSlash(filepath.Join(filepath.Base(s.tempDir), configFileName)),
	}
	s.ElementsMatch(expectedRelativePaths, relativePaths)
}
func (s *UploadTestSuite) TestCreateFilePathsDirNotExists() {
	// Input is invalid
	msg := "no such file or directory"
	if runtime.GOOS == "windows" {
		msg = "The system cannot find the file specified."
	}
	_, _, err := createFilePaths("nonexistent")
	assert.ErrorContains(s.T(), err, msg)
}

func (s *UploadTestSuite) TestUploadRecursive() {
	rescuedStdout := os.Stdout
	stdoutReader, stdoutWriter, _ := os.Pipe()
	os.Stdout = stdoutWriter

	rescuedStderr := os.Stderr
	stderrReader, stderrWriter, _ := os.Pipe()
	os.Stderr = stderrWriter

	// Test recursive upload
	assert.NoError(s.T(), Upload([]string{"upload", "--encrypt-with-key", s.publicKeyFilePath, "-r", s.filesToUploadDir}, s.configFilePath))

	_ = stdoutWriter.Close()
	os.Stdout = rescuedStdout
	uploadStdout, _ := io.ReadAll(stdoutReader)
	_ = stdoutReader.Close()

	_ = stderrWriter.Close()
	os.Stderr = rescuedStderr
	uploadStderr, _ := io.ReadAll(stderrReader)
	_ = stderrReader.Close()

	// Check logs that file was uploaded
	msg := fmt.Sprintf("file uploaded to %s/dummy/%s/%s.c4gh", s.s3MockHTTPServer.URL, filepath.Base(s.filesToUploadDir), filepath.Base(s.uploadTestFilePath))
	assert.Contains(s.T(), string(uploadStdout), msg)

	// Check in the logs for a warning that the file was unencrypted
	warnMsg := fmt.Sprintf("input file %s is not encrypted", filepath.Clean(s.uploadTestFilePath))
	assert.NotContains(s.T(), string(uploadStderr), warnMsg)

	// Check that file showed up in the s3 bucket correctly
	result, err := s.s3Client.ListObjects(context.TODO(), &s3.ListObjectsInput{
		Bucket: aws.String("dummy"),
	})
	if err != nil {
		s.FailNow("failed to list objects from s3", err)
	}
	assert.Equal(s.T(), aws.ToString(result.Contents[0].Key), fmt.Sprintf("%s/%s.c4gh", filepath.Base(s.filesToUploadDir), filepath.Base(s.uploadTestFilePath)))
}

func (s *UploadTestSuite) TestUploadTargetDir() {
	rescuedStdout := os.Stdout
	stdoutReader, stdoutWriter, _ := os.Pipe()
	os.Stdout = stdoutWriter

	// Test upload to a different folder
	targetPath := filepath.Join("a", "b", "c")
	assert.NoError(s.T(), Upload([]string{"upload", "--encrypt-with-key", s.publicKeyFilePath, s.uploadTestFilePath, "-targetDir", targetPath}, s.configFilePath))

	_ = stdoutWriter.Close()
	os.Stdout = rescuedStdout
	uploadStdout, _ := io.ReadAll(stdoutReader)
	_ = stdoutReader.Close()

	// Check logs that file was uploaded
	msg := fmt.Sprintf("file uploaded to %s/dummy/%s/%s.c4gh", s.s3MockHTTPServer.URL, filepath.ToSlash(targetPath), filepath.Base(s.uploadTestFilePath))
	assert.Contains(s.T(), string(uploadStdout), msg)

	// Check that file showed up in the s3 bucket correctly
	result, err := s.s3Client.ListObjects(context.TODO(), &s3.ListObjectsInput{
		Bucket: aws.String("dummy"),
	})
	if err != nil {
		s.FailNow("failed to list objects from s3", err)
	}
	assert.Equal(s.T(), aws.ToString(result.Contents[0].Key), fmt.Sprintf("%s/%s.c4gh", filepath.ToSlash(targetPath), filepath.Base(s.uploadTestFilePath)))
}
func (s *UploadTestSuite) TestUploadWithEncryption() {
	rescuedStdout := os.Stdout
	stdoutReader, stdoutWriter, _ := os.Pipe()
	os.Stdout = stdoutWriter

	rescuedStderr := os.Stderr
	stderrReader, stderrWriter, _ := os.Pipe()
	os.Stderr = stderrWriter

	assert.NoError(s.T(), Upload([]string{"upload", "--encrypt-with-key", s.publicKeyFilePath, s.uploadTestFilePath, "-targetDir", "someDir"}, s.configFilePath))

	_ = stdoutWriter.Close()
	os.Stdout = rescuedStdout
	uploadStdout, _ := io.ReadAll(stdoutReader)
	_ = stdoutReader.Close()

	_ = stderrWriter.Close()
	os.Stderr = rescuedStderr
	uploadStderr, _ := io.ReadAll(stderrReader)
	_ = stderrReader.Close()

	// Check logs that encrypted file was uploaded
	msg := fmt.Sprintf("file uploaded to %s/dummy/someDir/%s.c4gh", s.s3MockHTTPServer.URL, filepath.Base(s.uploadTestFilePath))
	assert.Contains(s.T(), string(uploadStdout), msg)

	// Check that file showed up in the s3 bucket correctly
	result, err := s.s3Client.ListObjects(context.TODO(), &s3.ListObjectsInput{
		Bucket: aws.String("dummy"),
	})
	if err != nil {
		s.FailNow("failed to list objects from s3", err)
	}
	assert.Equal(s.T(), aws.ToString(result.Contents[0].Key), "someDir/"+filepath.Base(s.uploadTestFilePath)+".c4gh")
	// Check that the respective unencrypted file was not uploaded
	assert.NotContains(s.T(), string(uploadStderr), fmt.Sprintf("Uploading %s with", s.uploadTestFilePath))
}

func (s *UploadTestSuite) TestUploadWithEncryptionRecursive() {
	rescuedStdout := os.Stdout
	stdoutReader, stdoutWriter, _ := os.Pipe()
	os.Stdout = stdoutWriter

	rescuedStderr := os.Stderr
	stderrReader, stderrWriter, _ := os.Pipe()
	os.Stderr = stderrWriter

	assert.NoError(s.T(), Upload([]string{"upload", "--encrypt-with-key", s.publicKeyFilePath, "-r", s.filesToUploadDir}, s.configFilePath))

	_ = stdoutWriter.Close()
	os.Stdout = rescuedStdout
	uploadStdout, _ := io.ReadAll(stdoutReader)
	_ = stdoutReader.Close()

	_ = stderrWriter.Close()
	os.Stderr = rescuedStderr
	uploadStderr, _ := io.ReadAll(stderrReader)
	_ = stderrReader.Close()

	// check if the host_base is in the output
	expectedHostBase := "Remote server (host_base): " + s.s3MockHTTPServer.URL
	assert.NotContains(s.T(), string(uploadStdout), expectedHostBase)
	assert.Contains(s.T(), string(uploadStderr), expectedHostBase)
}

func (s *UploadTestSuite) TestUploadWithEncryptionFileAlreadyExists() {
	// Check that trying to encrypt already encrypted files returns error and aborts
	encFile, err := os.CreateTemp(s.tempDir, "encFile")
	if err != nil {
		s.FailNow("failed to create test file", err)
	}
	if err := os.WriteFile(encFile.Name(), []byte("crypt4gh"), 0600); err != nil {
		s.FailNow("failed to write to test file", err)
	}
	_ = encFile.Close()

	assert.ErrorContains(s.T(), Upload([]string{"upload", "--encrypt-with-key", s.publicKeyFilePath, encFile.Name()}, s.configFilePath), "is already encrypted")
}
func (s *UploadTestSuite) TestUploadWithEncryptionInvalidPublicKey() {
	assert.EqualError(s.T(), Upload([]string{"upload", "--encrypt-with-key", s.uploadTestFilePath}, s.configFilePath), "no files to upload")
}
func (s *UploadTestSuite) TestUploadInvalidAccessTokenInConfigFile() {
	if err := os.WriteFile(s.configFilePath, fmt.Appendf([]byte{}, configFileFormat, "", s.s3MockHTTPServer.URL), 0600); err != nil {
		s.FailNow("failed to write s3cmd config file")
	}
	assert.EqualError(s.T(), Upload([]string{"upload", s.uploadTestFilePath}, s.configFilePath), "no access token supplied")
}
func (s *UploadTestSuite) TestUploadInvalidAccessTokenInEnvVariable() {
	_ = os.Setenv("ACCESSTOKEN", "BadToken")
	// Supplying an accesstoken as a ENV overrules the one in the config file
	assert.EqualError(s.T(), Upload([]string{"upload", s.uploadTestFilePath}, s.configFilePath), "could not parse token, reason: token contains an invalid number of segments")
}

func (s *UploadTestSuite) TestUploadValidAccessTokenInEnvVariable() {
	_ = os.Setenv("ACCESSTOKEN", s.accessToken)
	assert.NoError(s.T(), Upload([]string{"upload", "--encrypt-with-key", s.publicKeyFilePath, s.uploadTestFilePath}, s.configFilePath))
}

func (s *UploadTestSuite) TestUploadInvalidAccessTokenInFlag() {
	// Supplying an accesstoken as a parameter overrules the one in the config file
	assert.EqualError(s.T(), Upload([]string{"upload", "-accessToken", "BadToken", s.uploadTestFilePath}, s.configFilePath), "could not parse token, reason: token contains an invalid number of segments")
}

func (s *UploadTestSuite) TestUploadValidAccessTokenInFlag() {
	assert.NoError(s.T(), Upload([]string{"upload", "--encrypt-with-key", s.publicKeyFilePath, "-accessToken", s.accessToken, s.uploadTestFilePath}, s.configFilePath))
}

func (s *UploadTestSuite) TestRecursiveToDifferentTarget() {
	ctx := context.TODO()

	rescuedStdout := os.Stdout
	stdoutReader, stdoutWriter, _ := os.Pipe()
	os.Stdout = stdoutWriter

	// Test recursive upload to a different folder
	targetPath := filepath.Join("a", "b", "c")
	assert.NoError(s.T(), Upload([]string{"upload", "--encrypt-with-key", s.publicKeyFilePath, "-r", s.filesToUploadDir, "-targetDir", targetPath}, s.configFilePath))

	_ = stdoutWriter.Close()
	os.Stdout = rescuedStdout
	uploadStdout, _ := io.ReadAll(stdoutReader)
	_ = stdoutReader.Close()

	// Check logs that file was uploaded
	msg := fmt.Sprintf("file uploaded to %s/dummy/%s", s.s3MockHTTPServer.URL, filepath.ToSlash(filepath.Join(targetPath, filepath.Base(s.filesToUploadDir), filepath.Base(s.uploadTestFilePath)+".c4gh")))
	assert.Contains(s.T(), string(uploadStdout), msg)

	// Check that file showed up in the s3 bucket correctly
	result, err := s.s3Client.ListObjects(ctx, &s3.ListObjectsInput{
		Bucket: aws.String("dummy"),
	})
	if err != nil {
		s.FailNow("failed to list obects from s3", err)
	}
	assert.Equal(s.T(), filepath.ToSlash(filepath.Join(targetPath, filepath.Base(s.filesToUploadDir), filepath.Base(s.uploadTestFilePath)+".c4gh")), aws.ToString(result.Contents[0].Key))
}

func (s *UploadTestSuite) TestUploadInvalidCharactersInDirectoryName() {
	// Check that target dir names with invalid characters will not be accepted
	badchars := ":*?"
	// backslash is only allowed on windows
	if runtime.GOOS != "windows" {
		badchars += "\\"
	}
	for _, badc := range badchars {
		badchar := string(badc)
		targetDir := "test" + badchar + "dir"
		err := Upload([]string{"upload", "-targetDir", targetDir, "-r", s.uploadTestFilePath}, s.configFilePath)
		assert.Error(s.T(), err)
		assert.Equal(s.T(), targetDir+" is not a valid target directory", err.Error())
	}
}

func (s *UploadTestSuite) TestUploadInvalidCharactersInFileName() {
	// Filenames with :\?* can not be created on windows, skip the following tests
	if runtime.GOOS == "windows" {
		s.T().Skip("Skipping. Cannot create filenames with invalid characters on windows")
	}

	// Test that no files with invalid characters can be uploaded
	for _, badc := range "\\:*?" {
		badchar := string(badc)
		testfilepath := "test" + badchar + "file"

		testfile, err := os.Create(filepath.Join(s.tempDir, testfilepath))
		if err != nil {
			s.FailNow("failed to create test file", err)
		}
		err = os.WriteFile(testfile.Name(), []byte("content"), 0600)
		if err != nil {
			s.FailNow("failed to write to test file", err)
		}

		err = Upload([]string{"upload", "-r", testfile.Name()}, s.configFilePath)
		assert.Error(s.T(), err)
		assert.Equal(s.T(), fmt.Sprintf("filepath %v contains disallowed characters: %+v", testfilepath, badchar), err.Error())
	}
}

func (s *UploadTestSuite) generateDummyToken() string {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		s.FailNow("failed to generate key", err)
	}

	// Create the Claims
	claims := &jwt.StandardClaims{
		Issuer:    "test",
		ExpiresAt: time.Now().Add(2 * time.Minute).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	accessToken, err := token.SignedString(privateKey)
	if err != nil {
		s.FailNow("failed to sign token", err)
	}

	return accessToken
}

func (s *UploadTestSuite) TestUploadUnencryptedFileAborts() {
	expectedErr := fmt.Sprintf("input file %s is not encrypted. All files must be encrypted unless using -encrypt-with-key", s.uploadTestFilePath)
	assert.EqualError(s.T(), Upload([]string{"upload", s.uploadTestFilePath}, s.configFilePath), expectedErr)
}

func (s *UploadTestSuite) TestForceUnencryptedFlagRemoved() {
	assert.Nil(s.T(), Args.Lookup("force-unencrypted"))
}
