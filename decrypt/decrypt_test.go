package decrypt

import (
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

type DecryptTest struct {
	suite.Suite
	tempDir     string          // The directory this test will take place in
	testFiles   []encryptedFile // SetupTest will generate one file
	testKeyFile string          // SetupTest will generate key files used to encrypt / decrypt files in a test
}

type encryptedFile struct {
	encryptedFileName string
	decryptedFileName string
	content           []byte
}

func TestDecryptTestSuite(t *testing.T) {
	suite.Run(t, new(DecryptTest))
}

func (suite *DecryptTest) SetupTest() {
	// Clean any files created from previous test executions
	suite.testFiles = make([]encryptedFile, 0)

	var err error
	suite.tempDir, err = os.MkdirTemp(os.TempDir(), "sda-cli-test-decrypt-clean")
	if err != nil {
		suite.FailNow("failed to create temporary directory", err)
	}

	suite.testKeyFile = filepath.Join(suite.tempDir, "testkey")
	err = createKey.GenerateKeyPair(suite.testKeyFile, "")
	if err != nil {
		suite.FailNow("failed to generate key pair", err)
	}
	os.Setenv("C4GH_PASSWORD", "")

	suite.createNewEncryptedFile()
}

func (suite *DecryptTest) createNewEncryptedFile() {
	// create a test file...
	testFile, err := os.CreateTemp(suite.tempDir, "testfile-")
	if err != nil {
		suite.FailNow("failed to create test file in temporary directory", err)
	}
	fileContent := []byte(fmt.Sprintf("This is some fine content right here, in file: %s", testFile.Name()))
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

func (suite *DecryptTest) TearDownTest() {
	if err := os.RemoveAll(suite.tempDir); err != nil {
		suite.T().Error("failed to clean files")
	}

	if err := os.Remove("checksum_encrypted.md5"); err != nil {
		suite.FailNow("failed to delete checksum_encrypted.md5", err)
	}
	if err := os.Remove("checksum_unencrypted.md5"); err != nil {
		suite.FailNow("failed to delete checksum_unencrypted.md5", err)
	}
	if err := os.Remove("checksum_encrypted.sha256"); err != nil {
		suite.FailNow("failed to delete checksum_encrypted.sha256", err)
	}
	if err := os.Remove("checksum_unencrypted.sha256"); err != nil {
		suite.FailNow("failed to delete checksum_unencrypted.sha256", err)
	}

}

func (suite *DecryptTest) TestDecryptSuccess() {
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

func (suite *DecryptTest) TestDecryptExistingDecryptionFile() {
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

func (suite *DecryptTest) TestDecryptWithCleanArgSuccess() {
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

func (suite *DecryptTest) TestDecryptWithCleanArgWrongPassword() {
	os.Setenv("C4GH_PASSWORD", "wrong")

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
}
func (suite *DecryptTest) TestDecryptWrongPassword() {
	os.Setenv("C4GH_PASSWORD", "wrong")

	err := Decrypt([]string{
		"decrypt",
		"--clean",
		"-key",
		fmt.Sprintf("%s.sec.pem", suite.testKeyFile),
		suite.testFiles[0].encryptedFileName,
	})
	assert.Error(suite.T(), err)

	// Check that the decrypted file does not exist
	_, err = os.Stat(suite.testFiles[0].decryptedFileName)
	noSuchFileMessage := "no such file or directory"
	if runtime.GOOS == "windows" {
		noSuchFileMessage = "The system cannot find the file specified."
	}
	assert.ErrorContains(suite.T(), err, noSuchFileMessage)
}

func (suite *DecryptTest) TestDecryptMultipleFilesSuccess() {
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

func (suite *DecryptTest) TestDecryptMultipleFilesWithForceOverwriteArg() {
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

func (suite *DecryptTest) TestDecryptMultipleFilesOneNonExistentFile() {
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
