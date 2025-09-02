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

func (suite *UploadTestSuite) SetupTest() {
	// Reset flag values from any previous test invocation
	Args = flag.NewFlagSet("upload", flag.ContinueOnError)
	forceUnencrypted = Args.Bool("force-unencrypted", false, "Force uploading unencrypted files.")
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

	suite.accessToken = suite.generateDummyToken()
	suite.tempDir = suite.T().TempDir()

	// Create a fake s3 backend
	backend := s3mem.New()
	faker := gofakes3.New(backend)
	suite.s3MockHTTPServer = httptest.NewServer(faker.Server())

	// Configure S3 client
	awsConfig, err := config.LoadDefaultConfig(context.TODO(),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider("dummy", "dummy", suite.accessToken)),
		config.WithRegion("eu-central-1"),
		config.WithBaseEndpoint(suite.s3MockHTTPServer.URL),
	)
	if err != nil {
		suite.FailNow("failed to create aws config", err)
	}
	suite.s3Client = s3.NewFromConfig(awsConfig, func(o *s3.Options) {
		o.UsePathStyle = true
		o.EndpointOptions.DisableHTTPS = true
	})
	// Create bucket named dummy
	cparams := &s3.CreateBucketInput{
		Bucket: aws.String("dummy"),
	}
	if _, err := suite.s3Client.CreateBucket(context.TODO(), cparams); err != nil {
		suite.FailNow("failed to create s3 bucket", err)
	}

	suite.configFilePath = filepath.Join(suite.tempDir, "s3cmd.conf")
	if err := os.WriteFile(suite.configFilePath, fmt.Appendf([]byte{}, configFileFormat, suite.accessToken, suite.s3MockHTTPServer.URL), 0600); err != nil {
		suite.FailNow("failed to write s3cmd config file")
	}
	suite.filesToUploadDir, err = os.MkdirTemp(suite.tempDir, "upload_files")
	if err != nil {
		suite.FailNow("failed to create files to upload temp dir", err)
	}
	uploadTestFile, err := os.CreateTemp(suite.filesToUploadDir, "upload_test_file")
	if err != nil {
		suite.FailNow("failed to create test upload file")
	}
	if _, err := uploadTestFile.Write([]byte("test content")); err != nil {
		suite.FailNow("failed to write to test upload file")
	}
	_ = uploadTestFile.Close()
	suite.uploadTestFilePath = uploadTestFile.Name()

	// Generate a crypt4gh pub key
	pubKeyData, _, err := keys.GenerateKeyPair()
	if err != nil {
		suite.FailNow("Couldn't generate key pair", err)
	}
	// Write the keys to temporary files
	publicKey, err := os.CreateTemp(suite.tempDir, "pubkey-")
	if err != nil {
		suite.FailNow("Cannot create temporary public key file", err)
	}
	if err := keys.WriteCrypt4GHX25519PublicKey(publicKey, pubKeyData); err != nil {
		suite.FailNow("failed to write temporary public key file, %v", err)
	}
	_ = publicKey.Close()
	suite.publicKeyFilePath = publicKey.Name()
}

func (suite *UploadTestSuite) TearDownTest() {
	suite.s3MockHTTPServer.Close()
	// Remove hash files created by Encrypt
	_ = os.Remove("checksum_encrypted.md5")
	_ = os.Remove("checksum_unencrypted.md5")
	_ = os.Remove("checksum_encrypted.sha256")
	_ = os.Remove("checksum_unencrypted.sha256")
}

// Test calling upload without passing any files or target dir
func (suite *UploadTestSuite) TestUploadNoFiles() {
	assert.EqualError(suite.T(), Upload([]string{"upload"}, suite.configFilePath), "no files to upload")
}

// Test handling of mistakenly passing a filename as an upload folder
func (suite *UploadTestSuite) TestUploadFileNameAsTargetDir() {
	assert.EqualError(suite.T(), Upload([]string{"upload", "-targetDir", suite.configFilePath}, suite.configFilePath), fmt.Sprintf("%s is not a valid target directory", suite.configFilePath))
}

// Test handling of mistakenly passing a flag as an upload folder
func (suite *UploadTestSuite) TestUploadFlagAsTargetDir() {
	assert.EqualError(suite.T(), Upload([]string{"upload", "-targetDir", "-r"}, suite.configFilePath), "-r is not a valid target directory")
}

// Test passing target dir flag at the end
func (suite *UploadTestSuite) TestUploadTargetDirFlagAfterFileName() {
	assert.EqualError(suite.T(), Upload([]string{"upload", "-r", suite.uploadTestFilePath, "-targetDir", "somedir"}, suite.configFilePath), "unencrypted file found")
}

// Test passing target dir flag at the end with out value
func (suite *UploadTestSuite) TestUploadTargetDirFlagNoValueAfterFileName() {
	assert.EqualError(suite.T(), Upload([]string{"upload", suite.uploadTestFilePath, "-targetDir"}, suite.configFilePath), fmt.Sprintf("%s is not a valid target directory", suite.uploadTestFilePath))
}

// Test uploadFiles function without files
func (suite *UploadTestSuite) TestUploadFilesNoFiles() {
	loadedConfig, _ := helpers.LoadConfigFile(suite.configFilePath)
	assert.EqualError(suite.T(), uploadFiles([]string{}, []string{}, "", loadedConfig), "no files to upload")
}

func (suite *UploadTestSuite) TestCreateFilePathsFileAsInput() {
	_, _, err := createFilePaths(suite.uploadTestFilePath)
	assert.ErrorContains(suite.T(), err, "is not a directory")
}

func (suite *UploadTestSuite) TestCreateFilePaths() {
	absolutePaths, relativePaths, err := createFilePaths(suite.tempDir)
	assert.NoError(suite.T(), err)

	expectedAbsolutePaths := []string{
		suite.publicKeyFilePath,
		suite.uploadTestFilePath,
		suite.configFilePath,
	}
	suite.ElementsMatch(expectedAbsolutePaths, absolutePaths)

	uploadTestFileDir, uploadTestFileName := filepath.Split(suite.uploadTestFilePath)
	_, publicKeyfileName := filepath.Split(suite.publicKeyFilePath)
	_, configFileName := filepath.Split(suite.configFilePath)
	expectedRelativePaths := []string{
		filepath.ToSlash(filepath.Join(filepath.Base(suite.tempDir), publicKeyfileName)),
		filepath.ToSlash(filepath.Join(filepath.Base(suite.tempDir), filepath.Base(uploadTestFileDir), uploadTestFileName)),
		filepath.ToSlash(filepath.Join(filepath.Base(suite.tempDir), configFileName)),
	}
	suite.ElementsMatch(expectedRelativePaths, relativePaths)
}
func (suite *UploadTestSuite) TestCreateFilePathsDirNotExists() {
	// Input is invalid
	msg := "no such file or directory"
	if runtime.GOOS == "windows" {
		msg = "The system cannot find the file specified."
	}
	_, _, err := createFilePaths("nonexistent")
	assert.ErrorContains(suite.T(), err, msg)
}

func (suite *UploadTestSuite) TestUploadRecursive() {
	rescuedStdout := os.Stdout
	stdoutReader, stdoutWriter, _ := os.Pipe()
	os.Stdout = stdoutWriter

	rescuedStderr := os.Stderr
	stderrReader, stderrWriter, _ := os.Pipe()
	os.Stderr = stderrWriter

	// Test recursive upload
	assert.NoError(suite.T(), Upload([]string{"upload", "--force-unencrypted", "-r", suite.filesToUploadDir}, suite.configFilePath))

	_ = stdoutWriter.Close()
	os.Stdout = rescuedStdout
	uploadStdout, _ := io.ReadAll(stdoutReader)
	_ = stdoutReader.Close()

	_ = stderrWriter.Close()
	os.Stderr = rescuedStderr
	uploadStderr, _ := io.ReadAll(stderrReader)
	_ = stderrReader.Close()

	// Check logs that file was uploaded
	msg := fmt.Sprintf("file uploaded to %s/dummy/%s/%s", suite.s3MockHTTPServer.URL, filepath.Base(suite.filesToUploadDir), filepath.Base(suite.uploadTestFilePath))
	assert.Contains(suite.T(), string(uploadStdout), msg)

	// Check in the logs for a warning that the file was unencrypted
	warnMsg := fmt.Sprintf("input file %s is not encrypted", filepath.Clean(suite.uploadTestFilePath))
	assert.Contains(suite.T(), string(uploadStderr), warnMsg)

	// Check that file showed up in the s3 bucket correctly
	result, err := suite.s3Client.ListObjects(context.TODO(), &s3.ListObjectsInput{
		Bucket: aws.String("dummy"),
	})
	if err != nil {
		suite.FailNow("failed to list objects from s3", err)
	}
	assert.Equal(suite.T(), aws.ToString(result.Contents[0].Key), fmt.Sprintf("%s/%s", filepath.Base(suite.filesToUploadDir), filepath.Base(suite.uploadTestFilePath)))
}

func (suite *UploadTestSuite) TestUploadTargetDir() {
	rescuedStdout := os.Stdout
	stdoutReader, stdoutWriter, _ := os.Pipe()
	os.Stdout = stdoutWriter

	// Test upload to a different folder
	targetPath := filepath.Join("a", "b", "c")
	assert.NoError(suite.T(), Upload([]string{"upload", "--force-unencrypted", suite.uploadTestFilePath, "-targetDir", targetPath}, suite.configFilePath))

	_ = stdoutWriter.Close()
	os.Stdout = rescuedStdout
	uploadStdout, _ := io.ReadAll(stdoutReader)
	_ = stdoutReader.Close()

	// Check logs that file was uploaded
	msg := fmt.Sprintf("file uploaded to %s/dummy/%s/%s", suite.s3MockHTTPServer.URL, filepath.ToSlash(targetPath), filepath.Base(suite.uploadTestFilePath))
	assert.Contains(suite.T(), string(uploadStdout), msg)

	// Check that file showed up in the s3 bucket correctly
	result, err := suite.s3Client.ListObjects(context.TODO(), &s3.ListObjectsInput{
		Bucket: aws.String("dummy"),
	})
	if err != nil {
		suite.FailNow("failed to list objects from s3", err)
	}
	assert.Equal(suite.T(), aws.ToString(result.Contents[0].Key), fmt.Sprintf("%s/%s", filepath.ToSlash(targetPath), filepath.Base(suite.uploadTestFilePath)))
}
func (suite *UploadTestSuite) TestUploadWithEncryption() {
	rescuedStdout := os.Stdout
	stdoutReader, stdoutWriter, _ := os.Pipe()
	os.Stdout = stdoutWriter

	rescuedStderr := os.Stderr
	stderrReader, stderrWriter, _ := os.Pipe()
	os.Stderr = stderrWriter

	assert.NoError(suite.T(), Upload([]string{"upload", "--encrypt-with-key", suite.publicKeyFilePath, suite.uploadTestFilePath, "-targetDir", "someDir"}, suite.configFilePath))

	_ = stdoutWriter.Close()
	os.Stdout = rescuedStdout
	uploadStdout, _ := io.ReadAll(stdoutReader)
	_ = stdoutReader.Close()

	_ = stderrWriter.Close()
	os.Stderr = rescuedStderr
	uploadStderr, _ := io.ReadAll(stderrReader)
	_ = stderrReader.Close()

	// Check logs that encrypted file was uploaded
	msg := fmt.Sprintf("file uploaded to %s/dummy/someDir/%s.c4gh", suite.s3MockHTTPServer.URL, filepath.Base(suite.uploadTestFilePath))
	assert.Contains(suite.T(), string(uploadStdout), msg)

	// Check that file showed up in the s3 bucket correctly
	result, err := suite.s3Client.ListObjects(context.TODO(), &s3.ListObjectsInput{
		Bucket: aws.String("dummy"),
	})
	if err != nil {
		suite.FailNow("failed to list objects from s3", err)
	}
	assert.Equal(suite.T(), aws.ToString(result.Contents[0].Key), "someDir/"+filepath.Base(suite.uploadTestFilePath)+".c4gh")
	// Check that the respective unencrypted file was not uploaded
	assert.NotContains(suite.T(), string(uploadStderr), fmt.Sprintf("Uploading %s with", suite.uploadTestFilePath))
}

func (suite *UploadTestSuite) TestUploadWithEncryptionRecursive() {
	rescuedStdout := os.Stdout
	stdoutReader, stdoutWriter, _ := os.Pipe()
	os.Stdout = stdoutWriter

	rescuedStderr := os.Stderr
	stderrReader, stderrWriter, _ := os.Pipe()
	os.Stderr = stderrWriter

	assert.NoError(suite.T(), Upload([]string{"upload", "--force-unencrypted", "-r", suite.filesToUploadDir}, suite.configFilePath))

	_ = stdoutWriter.Close()
	os.Stdout = rescuedStdout
	uploadStdout, _ := io.ReadAll(stdoutReader)
	_ = stdoutReader.Close()

	_ = stderrWriter.Close()
	os.Stderr = rescuedStderr
	uploadStderr, _ := io.ReadAll(stderrReader)
	_ = stderrReader.Close()

	// check if the host_base is in the output
	expectedHostBase := "Remote server (host_base): " + suite.s3MockHTTPServer.URL
	assert.NotContains(suite.T(), string(uploadStdout), expectedHostBase)
	assert.Contains(suite.T(), string(uploadStderr), expectedHostBase)
}

func (suite *UploadTestSuite) TestUploadWithEncryptionFileAlreadyExists() {
	// Check that trying to encrypt already encrypted files returns error and aborts
	encFile, err := os.CreateTemp(suite.tempDir, "encFile")
	if err != nil {
		suite.FailNow("failed to create test file", err)
	}
	if err := os.WriteFile(encFile.Name(), []byte("crypt4gh"), 0600); err != nil {
		suite.FailNow("failed to write to test file", err)
	}
	_ = encFile.Close()

	assert.ErrorContains(suite.T(), Upload([]string{"upload", "--encrypt-with-key", suite.publicKeyFilePath, encFile.Name()}, suite.configFilePath), "is already encrypted")
}
func (suite *UploadTestSuite) TestUploadWithEncryptionInvalidPublicKey() {
	assert.EqualError(suite.T(), Upload([]string{"upload", "--encrypt-with-key", suite.uploadTestFilePath}, suite.configFilePath), "no files to upload")
}
func (suite *UploadTestSuite) TestUploadInvalidAccessTokenInConfigFile() {
	if err := os.WriteFile(suite.configFilePath, fmt.Appendf([]byte{}, configFileFormat, "", suite.s3MockHTTPServer.URL), 0600); err != nil {
		suite.FailNow("failed to write s3cmd config file")
	}
	assert.EqualError(suite.T(), Upload([]string{"upload", suite.uploadTestFilePath}, suite.configFilePath), "no access token supplied")
}
func (suite *UploadTestSuite) TestUploadInvalidAccessTokenInEnvVariable() {
	_ = os.Setenv("ACCESSTOKEN", "BadToken")
	// Supplying an accesstoken as a ENV overrules the one in the config file
	assert.EqualError(suite.T(), Upload([]string{"upload", suite.uploadTestFilePath}, suite.configFilePath), "could not parse token, reason: token contains an invalid number of segments")
}

func (suite *UploadTestSuite) TestUploadValidAccessTokenInEnvVariable() {
	_ = os.Setenv("ACCESSTOKEN", suite.accessToken)
	assert.NoError(suite.T(), Upload([]string{"upload", "--force-unencrypted", suite.uploadTestFilePath}, suite.configFilePath))

}
func (suite *UploadTestSuite) TestUploadInvalidAccessTokenInFlag() {
	// Supplying an accesstoken as a parameter overrules the one in the config file
	assert.EqualError(suite.T(), Upload([]string{"upload", "-accessToken", "BadToken", suite.uploadTestFilePath}, suite.configFilePath), "could not parse token, reason: token contains an invalid number of segments")
}
func (suite *UploadTestSuite) TestUploadValidAccessTokenInFlag() {
	assert.NoError(suite.T(), Upload([]string{"upload", "--force-unencrypted", "-accessToken", suite.accessToken, suite.uploadTestFilePath}, suite.configFilePath))
}

func (suite *UploadTestSuite) TestRecursiveToDifferentTarget() {
	ctx := context.TODO()

	rescuedStdout := os.Stdout
	stdoutReader, stdoutWriter, _ := os.Pipe()
	os.Stdout = stdoutWriter

	// Test recursive upload to a different folder
	targetPath := filepath.Join("a", "b", "c")
	assert.NoError(suite.T(), Upload([]string{"upload", "--force-unencrypted", "-r", suite.filesToUploadDir, "-targetDir", targetPath}, suite.configFilePath))

	_ = stdoutWriter.Close()
	os.Stdout = rescuedStdout
	uploadStdout, _ := io.ReadAll(stdoutReader)
	_ = stdoutReader.Close()

	// Check logs that file was uploaded
	msg := fmt.Sprintf("file uploaded to %s/dummy/%s", suite.s3MockHTTPServer.URL, filepath.ToSlash(filepath.Join(targetPath, filepath.Base(suite.filesToUploadDir), filepath.Base(suite.uploadTestFilePath))))
	assert.Contains(suite.T(), string(uploadStdout), msg)

	// Check that file showed up in the s3 bucket correctly
	result, err := suite.s3Client.ListObjects(ctx, &s3.ListObjectsInput{
		Bucket: aws.String("dummy"),
	})
	if err != nil {
		suite.FailNow("failed to list obects from s3", err)
	}
	assert.Equal(suite.T(), filepath.ToSlash(filepath.Join(targetPath, filepath.Base(suite.filesToUploadDir), filepath.Base(suite.uploadTestFilePath))), aws.ToString(result.Contents[0].Key))

}

func (suite *UploadTestSuite) TestUploadInvalidCharactersInDirectoryName() {
	// Check that target dir names with invalid characters will not be accepted
	badchars := ":*?"
	// backslash is only allowed on windows
	if runtime.GOOS != "windows" {
		badchars += "\\"
	}
	for _, badc := range badchars {
		badchar := string(badc)
		targetDir := "test" + badchar + "dir"
		err := Upload([]string{"upload", "--force-unencrypted", "-targetDir", targetDir, "-r", suite.uploadTestFilePath}, suite.configFilePath)
		assert.Error(suite.T(), err)
		assert.Equal(suite.T(), targetDir+" is not a valid target directory", err.Error())
	}
}
func (suite *UploadTestSuite) TestUploadInvalidCharactersInFileName() {
	// Filenames with :\?* can not be created on windows, skip the following tests
	if runtime.GOOS == "windows" {
		suite.T().Skip("Skipping. Cannot create filenames with invalid characters on windows")
	}

	// Test that no files with invalid characters can be uploaded
	for _, badc := range "\\:*?" {
		badchar := string(badc)
		testfilepath := "test" + badchar + "file"

		testfile, err := os.Create(filepath.Join(suite.tempDir, testfilepath))
		if err != nil {
			suite.FailNow("failed to create test file", err)
		}
		err = os.WriteFile(testfile.Name(), []byte("content"), 0600)
		if err != nil {
			suite.FailNow("failed to write to test file", err)
		}

		err = Upload([]string{"upload", "--force-unencrypted", "-r", testfile.Name()}, suite.configFilePath)
		assert.Error(suite.T(), err)
		assert.Equal(suite.T(), fmt.Sprintf("filepath %v contains disallowed characters: %+v", testfilepath, badchar), err.Error())
	}
}

func (suite *UploadTestSuite) generateDummyToken() string {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		suite.FailNow("failed to generate key", err)
	}

	// Create the Claims
	claims := &jwt.StandardClaims{
		Issuer:    "test",
		ExpiresAt: time.Now().Add(2 * time.Minute).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	accessToken, err := token.SignedString(privateKey)
	if err != nil {
		suite.FailNow("failed to sign token", err)
	}

	return accessToken
}
