package decrypt

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	createKey "github.com/NBISweden/sda-cli/create_key"
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

func (suite *DecryptTestSuite) SetupTest() {
	// Reset flags from previous test executions
	Args = flag.NewFlagSet("decrypt", flag.ContinueOnError)
	privateKeyFile = Args.String("key", "", "Private key to use for decrypting files.")
	forceOverwrite = Args.Bool("force-overwrite", false, "Force overwrite existing files.")
	clean = Args.Bool("clean", false, "Remove the encrypted file after decryption.")

	// Clean any files created from previous test executions
	suite.testFiles = make([]encryptedFile, 0)

	suite.tempDir = suite.T().TempDir()

	suite.testKeyFile = filepath.Join(suite.tempDir, "testkey")

	err := createKey.GenerateKeyPair(suite.testKeyFile, "test_pw")
	if err != nil {
		suite.FailNow("failed to generate key pair", err)
	}
	_ = os.Setenv("C4GH_PASSWORD", "test_pw")

	suite.privateKey, err = readPrivateKeyFile(fmt.Sprintf("%s.sec.pem", suite.testKeyFile), "test_pw")
	if err != nil {
		suite.FailNow("failed to read private key", err)
	}

	suite.createNewEncryptedFile()
}

func (suite *DecryptTestSuite) createNewEncryptedFile() {
	// create a test file...
	testFile, err := os.CreateTemp(suite.tempDir, "testfile-")
	if err != nil {
		suite.FailNow("failed to create test file in temporary directory", err)
	}
	fileContent := fmt.Appendf([]byte{}, "This is some fine content right here, in file: %s", testFile.Name())
	// ... and write the known content to it
	err = os.WriteFile(testFile.Name(), fileContent, 0600)
	if err != nil {
		suite.FailNow("failed to write content to test file", err)
	}

	_ = testFile.Close()

	encrypt.EmptyPublicKeyFileList()
	err = encrypt.Encrypt([]string{"encrypt", "-key", fmt.Sprintf("%s.pub.pem", suite.testKeyFile), testFile.Name()})
	if err != nil {
		suite.FailNow("failed to encrypt test file", err)
	}

	if err := os.Remove(testFile.Name()); err != nil {
		suite.FailNow("failed to remove decrypted file after encryption", err)
	}

	suite.testFiles = append(suite.testFiles, encryptedFile{
		encryptedFileName: fmt.Sprintf("%s.c4gh", testFile.Name()),
		decryptedFileName: testFile.Name(),
		content:           fileContent,
	})
}

func (suite *DecryptTestSuite) TearDownTest() {
	// The temporary directory cleanup is managed by the testing library as documented
	// at https://pkg.go.dev/testing#T.TempDir
	_ = os.Remove("checksum_encrypted.md5")
	_ = os.Remove("checksum_unencrypted.md5")
	_ = os.Remove("checksum_encrypted.sha256")
	_ = os.Remove("checksum_unencrypted.sha256")
}

func (suite *DecryptTestSuite) TestDecryptSuccess() {
	err := Decrypt([]string{
		"decrypt",
		"-key",
		fmt.Sprintf("%s.sec.pem", suite.testKeyFile),
		suite.testFiles[0].encryptedFileName,
	})

	assert.NoError(suite.T(), err)

	// Check that the encrypted file was removed
	_, err = os.Stat(suite.testFiles[0].encryptedFileName)
	assert.NoError(suite.T(), err, "encrypted file can not be found after decryption")

	// Check content of the decrypted file
	inFile, err := os.Open(suite.testFiles[0].decryptedFileName)
	assert.NoError(suite.T(), err, "unable to open decrypted file")
	fileData, err := io.ReadAll(inFile)
	_ = inFile.Close()
	assert.NoError(suite.T(), err, "unable to read decrypted file")
	assert.Equal(suite.T(), string(suite.testFiles[0].content), string(fileData))
}

func (suite *DecryptTestSuite) TestDecryptWithWrongPrivateKey() {

	wrongKeyFile := filepath.Join(suite.tempDir, "wrongKey")

	if err := createKey.GenerateKeyPair(wrongKeyFile, ""); err != nil {
		suite.FailNow("failed to generate key pair", err)
	}
	_ = os.Setenv("C4GH_PASSWORD", "")

	err := Decrypt([]string{
		"decrypt",
		"-key",
		fmt.Sprintf("%s.sec.pem", wrongKeyFile),
		suite.testFiles[0].encryptedFileName,
	})

	assert.NoError(suite.T(), err)

	// check that decrypted file does not exist, as decryption of file should not have taken place with the wrong key
	_, err = os.Stat(suite.testFiles[0].decryptedFileName)
	noSuchFileMessage := "no such file or directory"
	if runtime.GOOS == "windows" {
		noSuchFileMessage = "The system cannot find the file specified."
	}
	assert.ErrorContains(suite.T(), err, noSuchFileMessage)
}

func (suite *DecryptTestSuite) TestDecryptWithMalformedPrivateKey() {
	malformedKeyFile := fmt.Sprintf("%s/malformed_key.sec.pem", suite.tempDir)
	if err := os.WriteFile(malformedKeyFile, []byte(`
-----BEGIN CRYPT4GH ENCRYPTED PRIVATE KEY-----
MalformedKey
-----END CRYPT4GH ENCRYPTED PRIVATE KEY-----
`), 0600); err != nil {
		suite.FailNow("failed to write malformed private key")
	}

	err := Decrypt([]string{
		"decrypt",
		"-key",
		malformedKeyFile,
		suite.testFiles[0].encryptedFileName,
	})

	assert.EqualError(suite.T(), err, fmt.Sprintf("private key format not supported, file: %s", malformedKeyFile))
}
func (suite *DecryptTestSuite) TestDecryptWithMalformedPrivateKeyFile() {
	malformedKeyFile := fmt.Sprintf("%s/malformed_key.sec.pem", suite.tempDir)
	if err := os.WriteFile(malformedKeyFile, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, 0600); err != nil {
		suite.FailNow("failed to write malformed private key")
	}

	err := Decrypt([]string{
		"decrypt",
		"-key",
		malformedKeyFile,
		suite.testFiles[0].encryptedFileName,
	})

	assert.EqualError(suite.T(), err, fmt.Sprintf("read of unrecognized private key format failed; expected PEM encoded key, file: %s", malformedKeyFile))
}
func (suite *DecryptTestSuite) TestDecryptWithNonExistingPrivateKeyFile() {
	err := Decrypt([]string{
		"decrypt",
		"-key",
		fmt.Sprintf("%s/not-exist.sec.pem", suite.tempDir),
		suite.testFiles[0].encryptedFileName,
	})

	assert.EqualError(suite.T(), err, fmt.Sprintf("private key file %s/not-exist.sec.pem doesn't exist", suite.tempDir))
}
func (suite *DecryptTestSuite) TestDecryptExistingDecryptionFile() {
	// recreate unencrypted file with different content to verify it isn't overwritten
	if err := os.WriteFile(suite.testFiles[0].decryptedFileName, []byte("different content"), 0600); err != nil {
		suite.FailNow("failed to create test file in temporary directory")
	}

	err := Decrypt([]string{
		"decrypt",
		"-key",
		fmt.Sprintf("%s.sec.pem", suite.testKeyFile),
		suite.testFiles[0].encryptedFileName,
	})

	assert.NoError(suite.T(), err)

	// Check that the encrypted file was removed
	_, err = os.Stat(suite.testFiles[0].encryptedFileName)
	assert.NoError(suite.T(), err, "encrypted file can not be found after decryption")

	// Check content of the decrypted file
	inFile, err := os.Open(suite.testFiles[0].decryptedFileName)
	assert.NoError(suite.T(), err, "unable to open decrypted file")
	fileData, err := io.ReadAll(inFile)
	_ = inFile.Close()
	assert.NoError(suite.T(), err, "unable to read decrypted file")
	assert.Equal(suite.T(), "different content", string(fileData))
}

func (suite *DecryptTestSuite) TestDecryptWithCleanArgSuccess() {
	err := Decrypt([]string{
		"decrypt",
		"--clean",
		"-key",
		fmt.Sprintf("%s.sec.pem", suite.testKeyFile),
		suite.testFiles[0].encryptedFileName,
	})

	assert.NoError(suite.T(), err)

	// Check that the encrypted file was removed
	_, err = os.Stat(suite.testFiles[0].encryptedFileName)
	noSuchFileMessage := "no such file or directory"
	if runtime.GOOS == "windows" {
		noSuchFileMessage = "The system cannot find the file specified."
	}
	assert.ErrorContains(suite.T(), err, noSuchFileMessage)

	// Check content of the decrypted file
	inFile, err := os.Open(suite.testFiles[0].decryptedFileName)
	assert.NoError(suite.T(), err, "unable to open decrypted file")
	fileData, err := io.ReadAll(inFile)
	_ = inFile.Close()
	assert.NoError(suite.T(), err, "unable to read decrypted file")
	assert.Equal(suite.T(), string(suite.testFiles[0].content), string(fileData))
}

func (suite *DecryptTestSuite) TestDecryptWithCleanArgWrongPassword() {
	_ = os.Setenv("C4GH_PASSWORD", "wrong")

	err := Decrypt([]string{
		"decrypt",
		"--clean",
		"-key",
		fmt.Sprintf("%s.sec.pem", suite.testKeyFile),
		suite.testFiles[0].encryptedFileName,
	})
	assert.Error(suite.T(), err)

	// Check that the encrypted file was not removed
	_, err = os.Stat(suite.testFiles[0].encryptedFileName)
	assert.NoError(suite.T(), err, "encrypted file can not be found after decrypt failure")

	// Check that the decrypted file does not exist
	_, err = os.Stat(suite.testFiles[0].decryptedFileName)
	noSuchFileMessage := "no such file or directory"
	if runtime.GOOS == "windows" {
		noSuchFileMessage = "The system cannot find the file specified."
	}
	assert.ErrorContains(suite.T(), err, noSuchFileMessage)
}

func (suite *DecryptTestSuite) TestDecryptMultipleFilesSuccess() {
	// Generate 2 additional files besides the one file generated by SetupTest
	suite.createNewEncryptedFile()
	suite.createNewEncryptedFile()

	err := Decrypt([]string{
		"decrypt",
		"-key",
		fmt.Sprintf("%s.sec.pem", suite.testKeyFile),
		suite.testFiles[0].encryptedFileName,
		suite.testFiles[1].encryptedFileName,
		suite.testFiles[2].encryptedFileName,
	})
	assert.NoError(suite.T(), err)

	// Check the decrypted files
	for _, file := range suite.testFiles {

		// Check that the encrypted file was remains
		_, err = os.Stat(file.encryptedFileName)
		assert.NoError(suite.T(), err, "encrypted file can not be found after decrypt")

		// Check content of the decrypted file
		inFile, err := os.Open(file.decryptedFileName)
		assert.NoError(suite.T(), err, "unable to open decrypted file")
		fileData, err := io.ReadAll(inFile)
		_ = inFile.Close()
		assert.NoError(suite.T(), err, "unable to read decrypted file")
		assert.Equal(suite.T(), string(file.content), string(fileData))

	}
}

func (suite *DecryptTestSuite) TestDecryptMultipleFilesWithForceOverwriteArg() {
	// Generate 2 additional files besides the one file generated by SetupTest
	suite.createNewEncryptedFile()
	suite.createNewEncryptedFile()

	// recreate unencrypted files with different content such they can be overwritten
	if err := os.WriteFile(suite.testFiles[0].decryptedFileName, []byte("different content"), 0600); err != nil {
		suite.FailNow("failed to create test file in temporary directory")
	}
	if err := os.WriteFile(suite.testFiles[1].decryptedFileName, []byte("different content"), 0600); err != nil {
		suite.FailNow("failed to create test file in temporary directory")
	}
	if err := os.WriteFile(suite.testFiles[2].decryptedFileName, []byte("different content"), 0600); err != nil {
		suite.FailNow("failed to create test file in temporary directory")
	}

	err := Decrypt([]string{
		"decrypt",
		"--force-overwrite",
		"-key",
		fmt.Sprintf("%s.sec.pem", suite.testKeyFile),
		suite.testFiles[0].encryptedFileName,
		suite.testFiles[1].encryptedFileName,
		suite.testFiles[2].encryptedFileName,
	})
	assert.NoError(suite.T(), err)

	// Check the decrypted files
	for _, file := range suite.testFiles { // Check file2.txt and file3.txt
		// Check that the encrypted file was remains
		_, err = os.Stat(file.encryptedFileName)
		assert.NoError(suite.T(), err, "encrypted file can not be found after decrypt")

		// Check content of the decrypted file
		inFile, err := os.Open(file.decryptedFileName)
		assert.NoError(suite.T(), err, "unable to open decrypted file")
		fileData, err := io.ReadAll(inFile)
		_ = inFile.Close()
		assert.NoError(suite.T(), err, "unable to read decrypted file")
		assert.Equal(suite.T(), string(file.content), string(fileData))
	}
}

func (suite *DecryptTestSuite) TestDecryptMultipleFilesOneNonExistentFile() {
	// Generate 2 additional files besides the one file generated by SetupTest
	suite.createNewEncryptedFile()
	suite.createNewEncryptedFile()

	err := Decrypt([]string{
		"decrypt",
		"-key",
		fmt.Sprintf("%s.sec.pem", suite.testKeyFile),
		suite.testFiles[0].encryptedFileName,
		suite.testFiles[1].encryptedFileName,
		suite.testFiles[2].encryptedFileName,
		"nonexistent_file.c4gh",
	})
	assert.NoError(suite.T(), err)

	// Check the decrypted files
	for _, file := range suite.testFiles { // Check file2.txt and file3.txt
		// Check that the encrypted file was remains
		_, err = os.Stat(file.encryptedFileName)
		assert.NoError(suite.T(), err, "encrypted file can not be found after decrypt")

		// Check content of the decrypted file
		inFile, err := os.Open(file.decryptedFileName)
		assert.NoError(suite.T(), err, "unable to open decrypted file")
		fileData, err := io.ReadAll(inFile)
		_ = inFile.Close()
		assert.NoError(suite.T(), err, "unable to read decrypted file")
		assert.Equal(suite.T(), string(file.content), string(fileData))
	}
}

func (suite *DecryptTestSuite) TestReadPrivateKeyFile() {
	for _, test := range []struct {
		testName         string
		fileName         string
		password         string
		expectedErrorMsg error
	}{
		{
			testName:         "FileNotExists",
			fileName:         suite.testKeyFile,
			password:         "Doesnt matter",
			expectedErrorMsg: fmt.Errorf("private key file %s doesn't exist", suite.testKeyFile),
		},
		{
			testName:         "NotAKeyFile",
			fileName:         suite.testFiles[0].encryptedFileName,
			password:         "Doesnt matter",
			expectedErrorMsg: fmt.Errorf("read of unrecognized private key format failed; expected PEM encoded key, file: %s", suite.testFiles[0].encryptedFileName),
		},
		{
			testName:         "ReadPublicKey",
			fileName:         fmt.Sprintf("%s.pub.pem", suite.testKeyFile),
			password:         "Doesnt matter",
			expectedErrorMsg: fmt.Errorf("private key format not supported, file: %s", fmt.Sprintf("%s.pub.pem", suite.testKeyFile)),
		},
		{
			testName:         "WrongPassword",
			fileName:         fmt.Sprintf("%s.sec.pem", suite.testKeyFile),
			password:         "wrong",
			expectedErrorMsg: fmt.Errorf("chacha20poly1305: message authentication failed, file: %s", fmt.Sprintf("%s.sec.pem", suite.testKeyFile)),
		},
		{
			testName:         "Successful",
			fileName:         fmt.Sprintf("%s.sec.pem", suite.testKeyFile),
			password:         "test_pw",
			expectedErrorMsg: nil,
		},
	} {
		suite.T().Run(test.testName, func(t *testing.T) {
			_, err := readPrivateKeyFile(test.fileName, test.password)
			assert.Equal(t, err, test.expectedErrorMsg)
		})
	}
}

func (suite *DecryptTestSuite) TestDecryptFileSuccess() {
	decryptedFile := filepath.Join(suite.tempDir, "decrypted_file")

	err := decryptFile(suite.testFiles[0].encryptedFileName, decryptedFile, *suite.privateKey)
	assert.NoError(suite.T(), err)

	// Check content of the decrypted file
	inFile, err := os.Open(decryptedFile)
	assert.NoError(suite.T(), err, "unable to open decrypted file")
	fileData, err := io.ReadAll(inFile)
	_ = inFile.Close()
	assert.NoError(suite.T(), err, "unable to read decrypted file")
	assert.Equal(suite.T(), fileData, suite.testFiles[0].content)

}
func (suite *DecryptTestSuite) TestDecryptFileMalformedKey() {
	decryptedFile := filepath.Join(suite.tempDir, "decrypted_file")

	suite.privateKey = &[32]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}

	err := decryptFile(suite.testFiles[0].encryptedFileName, decryptedFile, *suite.privateKey)
	assert.EqualError(suite.T(), err, "could not create cryp4gh reader: could not find matching public key header, decryption failed")
}

func (suite *DecryptTestSuite) TestDecryptFileNonExistentFile() {
	msg := "no such file or directory"
	if runtime.GOOS == "windows" {
		msg = "The system cannot find the file specified."
	}
	err := decryptFile(filepath.Join(suite.tempDir, "non-existent"), "output_file", *suite.privateKey)
	assert.ErrorContains(suite.T(), err, msg)
}
