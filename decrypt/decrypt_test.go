package decrypt

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	createkey "github.com/NBISweden/sda-cli/create_key"
	"github.com/NBISweden/sda-cli/encrypt"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type DecryptTestSuite struct {
	suite.Suite
	tempDir     string          // The directory this test will take place in
	testFiles   []encryptedFile // SetupTest will generate one file
	testKeyFile string          // SetupTest will generate key files used to encrypt / decrypt files in a test
	privateKey  *[32]byte
}

type encryptedFile struct {
	encryptedFileName string
	decryptedFileName string
	content           []byte
}

func TestDecryptTestSuite(t *testing.T) {
	suite.Run(t, new(DecryptTestSuite))
}

func (s *DecryptTestSuite) SetupTest() {
	// Reset flags from previous test executions
	os.Args = []string{"", "decrypt"}
	decryptCmd.Flag("key").Value.Set("")
	decryptCmd.Flag("force-overwrite").Value.Set("false")
	decryptCmd.Flag("clean").Value.Set("false")
	decryptCmd.Root().Flag("config").Value.Set("")

	// Clean any files created from previous test executions
	s.testFiles = make([]encryptedFile, 0)

	s.tempDir = s.T().TempDir()

	s.testKeyFile = filepath.Join(s.tempDir, "testkey")

	err := createkey.GenerateKeyPair(s.testKeyFile, "test_pw")
	if err != nil {
		s.FailNow("failed to generate key pair", err)
	}
	_ = os.Setenv("C4GH_PASSWORD", "test_pw")

	s.privateKey, err = readPrivateKeyFile(fmt.Sprintf("%s.sec.pem", s.testKeyFile), "test_pw")
	if err != nil {
		s.FailNow("failed to read private key", err)
	}

	s.createNewEncryptedFile()
}

func (s *DecryptTestSuite) createNewEncryptedFile() {
	// create a test file...
	testFile, err := os.CreateTemp(s.tempDir, "testfile-")
	if err != nil {
		s.FailNow("failed to create test file in temporary directory", err)
	}
	fileContent := fmt.Appendf([]byte{}, "This is some fine content right here, in file: %s", testFile.Name())
	// ... and write the known content to it
	err = os.WriteFile(testFile.Name(), fileContent, 0600)
	if err != nil {
		s.FailNow("failed to write content to test file", err)
	}

	_ = testFile.Close()

	encrypt.EmptyPublicKeyFileList()
	encrypt.SetFlags("key", fmt.Sprintf("%s.pub.pem", s.testKeyFile))
	err = encrypt.Encrypt([]string{testFile.Name()})
	if err != nil {
		s.FailNow("failed to encrypt test file", err)
	}

	if err := os.Remove(testFile.Name()); err != nil {
		s.FailNow("failed to remove decrypted file after encryption", err)
	}

	s.testFiles = append(s.testFiles, encryptedFile{
		encryptedFileName: fmt.Sprintf("%s.c4gh", testFile.Name()),
		decryptedFileName: testFile.Name(),
		content:           fileContent,
	})
}

func (s *DecryptTestSuite) TearDownTest() {
	// The temporary directory cleanup is managed by the testing library as documented
	// at https://pkg.go.dev/testing#T.TempDir
	_ = os.Remove("checksum_encrypted.md5")
	_ = os.Remove("checksum_unencrypted.md5")
	_ = os.Remove("checksum_encrypted.sha256")
	_ = os.Remove("checksum_unencrypted.sha256")
}

func (s *DecryptTestSuite) TestDecryptSuccess() {
	os.Args = []string{"", "decrypt", s.testFiles[0].encryptedFileName}
	decryptCmd.Flag("key").Value.Set(fmt.Sprintf("%s.sec.pem", s.testKeyFile))
	err := decryptCmd.Execute()

	assert.NoError(s.T(), err)

	// Check that the encrypted file was removed
	_, err = os.Stat(s.testFiles[0].encryptedFileName)
	assert.NoError(s.T(), err, "encrypted file can not be found after decryption")

	// Check content of the decrypted file
	inFile, err := os.Open(s.testFiles[0].decryptedFileName)
	assert.NoError(s.T(), err, "unable to open decrypted file")
	fileData, err := io.ReadAll(inFile)
	_ = inFile.Close()
	assert.NoError(s.T(), err, "unable to read decrypted file")
	assert.Equal(s.T(), string(s.testFiles[0].content), string(fileData))
}

func (s *DecryptTestSuite) TestDecryptWithWrongPrivateKey() {
	wrongKeyFile := filepath.Join(s.tempDir, "wrongKey")

	if err := createkey.GenerateKeyPair(wrongKeyFile, ""); err != nil {
		s.FailNow("failed to generate key pair", err)
	}
	_ = os.Setenv("C4GH_PASSWORD", "")

	os.Args = []string{s.testFiles[0].encryptedFileName}
	decryptCmd.Flag("key").Value.Set(fmt.Sprintf("%s.sec.pem", wrongKeyFile))
	err := decryptCmd.Execute()

	assert.NoError(s.T(), err)

	// check that decrypted file does not exist, as decryption of file should not have taken place with the wrong key
	_, err = os.Stat(s.testFiles[0].decryptedFileName)
	noSuchFileMessage := "no such file or directory"
	if runtime.GOOS == "windows" {
		noSuchFileMessage = "The system cannot find the file specified."
	}
	assert.ErrorContains(s.T(), err, noSuchFileMessage)
}

func (s *DecryptTestSuite) TestDecryptWithMalformedPrivateKey() {
	malformedKeyFile := fmt.Sprintf("%s/malformed_key.sec.pem", s.tempDir)
	if err := os.WriteFile(malformedKeyFile, []byte(`
-----BEGIN CRYPT4GH ENCRYPTED PRIVATE KEY-----
MalformedKey
-----END CRYPT4GH ENCRYPTED PRIVATE KEY-----
`), 0600); err != nil {
		s.FailNow("failed to write malformed private key")
	}

	os.Args = []string{"", "decrypt", s.testFiles[0].encryptedFileName}
	decryptCmd.Flag("key").Value.Set(malformedKeyFile)
	err := decryptCmd.Execute()

	assert.EqualError(s.T(), err, fmt.Sprintf("private key format not supported, file: %s", malformedKeyFile))
}
func (s *DecryptTestSuite) TestDecryptWithMalformedPrivateKeyFile() {
	malformedKeyFile := fmt.Sprintf("%s/malformed_key.sec.pem", s.tempDir)
	if err := os.WriteFile(malformedKeyFile, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, 0600); err != nil {
		s.FailNow("failed to write malformed private key")
	}

	os.Args = []string{"", "decrypt", s.testFiles[0].encryptedFileName}
	decryptCmd.Flag("key").Value.Set(malformedKeyFile)
	err := decryptCmd.Execute()

	assert.EqualError(s.T(), err, fmt.Sprintf("read of unrecognized private key format failed; expected PEM encoded key, file: %s", malformedKeyFile))
}
func (s *DecryptTestSuite) TestDecryptWithNonExistingPrivateKeyFile() {
	os.Args = []string{"", "decrypt", s.testFiles[0].encryptedFileName}
	decryptCmd.Flag("key").Value.Set(fmt.Sprintf("%s/not-exist.sec.pem", s.tempDir))
	err := decryptCmd.Execute()

	assert.EqualError(s.T(), err, fmt.Sprintf("private key file %s/not-exist.sec.pem doesn't exist", s.tempDir))
}
func (s *DecryptTestSuite) TestDecryptExistingDecryptionFile() {
	// recreate unencrypted file with different content to verify it isn't overwritten
	if err := os.WriteFile(s.testFiles[0].decryptedFileName, []byte("different content"), 0600); err != nil {
		s.FailNow("failed to create test file in temporary directory")
	}

	os.Args = []string{"", "decrypt", s.testFiles[0].encryptedFileName}
	decryptCmd.Flag("key").Value.Set(fmt.Sprintf("%s.sec.pem", s.testKeyFile))
	err := decryptCmd.Execute()

	assert.NoError(s.T(), err)

	// Check that the encrypted file was removed
	_, err = os.Stat(s.testFiles[0].encryptedFileName)
	assert.NoError(s.T(), err, "encrypted file can not be found after decryption")

	// Check content of the decrypted file
	inFile, err := os.Open(s.testFiles[0].decryptedFileName)
	assert.NoError(s.T(), err, "unable to open decrypted file")
	fileData, err := io.ReadAll(inFile)
	_ = inFile.Close()
	assert.NoError(s.T(), err, "unable to read decrypted file")
	assert.Equal(s.T(), "different content", string(fileData))
}

func (s *DecryptTestSuite) TestDecryptWithCleanArgSuccess() {
	os.Args = []string{"", "decrypt", s.testFiles[0].encryptedFileName}
	decryptCmd.Flag("clean").Value.Set("true")
	decryptCmd.Flag("key").Value.Set(fmt.Sprintf("%s.sec.pem", s.testKeyFile))
	err := decryptCmd.Execute()

	assert.NoError(s.T(), err)

	// Check that the encrypted file was removed
	_, err = os.Stat(s.testFiles[0].encryptedFileName)
	noSuchFileMessage := "no such file or directory"
	if runtime.GOOS == "windows" {
		noSuchFileMessage = "The system cannot find the file specified."
	}
	assert.ErrorContains(s.T(), err, noSuchFileMessage)

	// Check content of the decrypted file
	inFile, err := os.Open(s.testFiles[0].decryptedFileName)
	assert.NoError(s.T(), err, "unable to open decrypted file")
	fileData, err := io.ReadAll(inFile)
	_ = inFile.Close()
	assert.NoError(s.T(), err, "unable to read decrypted file")
	assert.Equal(s.T(), string(s.testFiles[0].content), string(fileData))
}

func (s *DecryptTestSuite) TestDecryptWithCleanArgWrongPassword() {
	_ = os.Setenv("C4GH_PASSWORD", "wrong")

	os.Args = []string{"", "decrypt", s.testFiles[0].encryptedFileName}
	decryptCmd.Flag("clean").Value.Set("true")
	decryptCmd.Flag("key").Value.Set(fmt.Sprintf("%s.sec.pem", s.testKeyFile))
	err := decryptCmd.Execute()

	assert.Error(s.T(), err)

	// Check that the encrypted file was not removed
	_, err = os.Stat(s.testFiles[0].encryptedFileName)
	assert.NoError(s.T(), err, "encrypted file can not be found after decrypt failure")

	// Check that the decrypted file does not exist
	_, err = os.Stat(s.testFiles[0].decryptedFileName)
	noSuchFileMessage := "no such file or directory"
	if runtime.GOOS == "windows" {
		noSuchFileMessage = "The system cannot find the file specified."
	}
	assert.ErrorContains(s.T(), err, noSuchFileMessage)
}

func (s *DecryptTestSuite) TestDecryptMultipleFilesSuccess() {
	// Generate 2 additional files besides the one file generated by SetupTest
	s.createNewEncryptedFile()
	s.createNewEncryptedFile()
	os.Args = []string{"", "decrypt",
		s.testFiles[0].encryptedFileName,
		s.testFiles[1].encryptedFileName,
		s.testFiles[2].encryptedFileName,
	}

	decryptCmd.Flag("key").Value.Set(fmt.Sprintf("%s.sec.pem", s.testKeyFile))
	err := decryptCmd.Execute()
	assert.NoError(s.T(), err)

	for _, file := range s.testFiles {
		_, err = os.Stat(file.encryptedFileName)
		assert.NoError(s.T(), err, "encrypted file can not be found after decrypt")

		inFile, err := os.Open(file.decryptedFileName)
		assert.NoError(s.T(), err, "unable to open decrypted file")
		fileData, err := io.ReadAll(inFile)
		_ = inFile.Close()
		assert.NoError(s.T(), err, "unable to read decrypted file")
		assert.Equal(s.T(), string(file.content), string(fileData))
	}
}

func (s *DecryptTestSuite) TestDecryptMultipleFilesWithForceOverwriteArg() {
	// Generate 2 additional files besides the one file generated by SetupTest
	s.createNewEncryptedFile()
	s.createNewEncryptedFile()

	// recreate unencrypted files with different content such they can be overwritten
	if err := os.WriteFile(s.testFiles[0].decryptedFileName, []byte("different content"), 0600); err != nil {
		s.FailNow("failed to create test file in temporary directory")
	}
	if err := os.WriteFile(s.testFiles[1].decryptedFileName, []byte("different content"), 0600); err != nil {
		s.FailNow("failed to create test file in temporary directory")
	}
	if err := os.WriteFile(s.testFiles[2].decryptedFileName, []byte("different content"), 0600); err != nil {
		s.FailNow("failed to create test file in temporary directory")
	}

	os.Args = []string{"", "decrypt",
		s.testFiles[0].encryptedFileName,
		s.testFiles[1].encryptedFileName,
		s.testFiles[2].encryptedFileName,
	}
	decryptCmd.Flag("key").Value.Set(fmt.Sprintf("%s.sec.pem", s.testKeyFile))
	decryptCmd.Flag("force-overwrite").Value.Set("true")
	err := decryptCmd.Execute()

	assert.NoError(s.T(), err)

	// Check the decrypted files
	for _, file := range s.testFiles { // Check file2.txt and file3.txt
		// Check that the encrypted file was remains
		_, err = os.Stat(file.encryptedFileName)
		assert.NoError(s.T(), err, "encrypted file can not be found after decrypt")

		// Check content of the decrypted file
		inFile, err := os.Open(file.decryptedFileName)
		assert.NoError(s.T(), err, "unable to open decrypted file")
		fileData, err := io.ReadAll(inFile)
		_ = inFile.Close()
		assert.NoError(s.T(), err, "unable to read decrypted file")
		assert.Equal(s.T(), string(file.content), string(fileData))
	}
}

func (s *DecryptTestSuite) TestDecryptMultipleFilesOneNonExistentFile() {
	// Generate 2 additional files besides the one file generated by SetupTest
	s.createNewEncryptedFile()
	s.createNewEncryptedFile()
	os.Args = []string{"", "decrypt",
		s.testFiles[0].encryptedFileName,
		s.testFiles[1].encryptedFileName,
		s.testFiles[2].encryptedFileName,
		"nonexistent_file.c4gh",
	}

	decryptCmd.Flag("key").Value.Set(fmt.Sprintf("%s.sec.pem", s.testKeyFile))
	err := decryptCmd.Execute()

	assert.NoError(s.T(), err)

	// Check the decrypted files
	for _, file := range s.testFiles { // Check file2.txt and file3.txt
		// Check that the encrypted file was remains
		_, err = os.Stat(file.encryptedFileName)
		assert.NoError(s.T(), err, "encrypted file can not be found after decrypt")

		// Check content of the decrypted file
		inFile, err := os.Open(file.decryptedFileName)
		assert.NoError(s.T(), err, "unable to open decrypted file")
		fileData, err := io.ReadAll(inFile)
		_ = inFile.Close()
		assert.NoError(s.T(), err, "unable to read decrypted file")
		assert.Equal(s.T(), string(file.content), string(fileData))
	}
}

func (s *DecryptTestSuite) TestReadPrivateKeyFile() {
	for _, test := range []struct {
		testName         string
		fileName         string
		password         string
		expectedErrorMsg error
	}{
		{
			testName:         "FileNotExists",
			fileName:         s.testKeyFile,
			password:         "Doesnt matter",
			expectedErrorMsg: fmt.Errorf("private key file %s doesn't exist", s.testKeyFile),
		},
		{
			testName:         "NotAKeyFile",
			fileName:         s.testFiles[0].encryptedFileName,
			password:         "Doesnt matter",
			expectedErrorMsg: fmt.Errorf("read of unrecognized private key format failed; expected PEM encoded key, file: %s", s.testFiles[0].encryptedFileName),
		},
		{
			testName:         "ReadPublicKey",
			fileName:         fmt.Sprintf("%s.pub.pem", s.testKeyFile),
			password:         "Doesnt matter",
			expectedErrorMsg: fmt.Errorf("private key format not supported, file: %s", fmt.Sprintf("%s.pub.pem", s.testKeyFile)),
		},
		{
			testName:         "WrongPassword",
			fileName:         fmt.Sprintf("%s.sec.pem", s.testKeyFile),
			password:         "wrong",
			expectedErrorMsg: fmt.Errorf("chacha20poly1305: message authentication failed, file: %s", fmt.Sprintf("%s.sec.pem", s.testKeyFile)),
		},
		{
			testName:         "Successful",
			fileName:         fmt.Sprintf("%s.sec.pem", s.testKeyFile),
			password:         "test_pw",
			expectedErrorMsg: nil,
		},
	} {
		s.T().Run(test.testName, func(t *testing.T) {
			_, err := readPrivateKeyFile(test.fileName, test.password)
			assert.Equal(t, err, test.expectedErrorMsg)
		})
	}
}

func (s *DecryptTestSuite) TestDecryptFileSuccess() {
	decryptedFile := filepath.Join(s.tempDir, "decrypted_file")

	err := decryptFile(s.testFiles[0].encryptedFileName, decryptedFile, *s.privateKey)
	assert.NoError(s.T(), err)

	// Check content of the decrypted file
	inFile, err := os.Open(decryptedFile)
	assert.NoError(s.T(), err, "unable to open decrypted file")
	fileData, err := io.ReadAll(inFile)
	_ = inFile.Close()
	assert.NoError(s.T(), err, "unable to read decrypted file")
	assert.Equal(s.T(), fileData, s.testFiles[0].content)
}

func (s *DecryptTestSuite) TestDecryptFileMalformedKey() {
	decryptedFile := filepath.Join(s.tempDir, "decrypted_file")

	s.privateKey = &[32]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}

	err := decryptFile(s.testFiles[0].encryptedFileName, decryptedFile, *s.privateKey)
	assert.EqualError(s.T(), err, "could not create cryp4gh reader: could not find matching public key header, decryption failed")
}

func (s *DecryptTestSuite) TestDecryptFileNonExistentFile() {
	msg := "no such file or directory"
	if runtime.GOOS == "windows" {
		msg = "The system cannot find the file specified."
	}
	err := decryptFile(filepath.Join(s.tempDir, "non-existent"), "output_file", *s.privateKey)
	assert.ErrorContains(s.T(), err, msg)
}
