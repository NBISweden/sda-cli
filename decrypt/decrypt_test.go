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

type DecryptTests struct {
	suite.Suite
	tempDir     string
	fileContent []byte
	testFile    *os.File
}

func TestDecryptTestSuite(t *testing.T) {
	suite.Run(t, new(DecryptTests))
}

func (suite *DecryptTests) SetupTest() {
	var err error
	// Create a temporary directory for our files
	suite.tempDir, err = os.MkdirTemp(os.TempDir(), "sda-cli-test-")
	assert.NoError(suite.T(), err)

	// create a test file...
	suite.testFile, err = os.CreateTemp(suite.tempDir, "testfile-")
	assert.NoError(suite.T(), err)

	// ... create some content ...
	suite.fileContent = []byte("This is some fine content right here.")
	// ... and write the known content to it
	err = os.WriteFile(suite.testFile.Name(), suite.fileContent, 0600)
	assert.NoError(suite.T(), err)
}

func (suite *DecryptTests) TearDownTest() {
	os.Remove(suite.tempDir)
}

func (suite *DecryptTests) TestreadPrivateKeyFile() {
	testKeyFile := filepath.Join(suite.tempDir, "testkey")
	// generate key files
	err := createKey.GenerateKeyPair(testKeyFile, "test")
	assert.NoError(suite.T(), err)

	// Test reading a non-existent key
	_, err = readPrivateKeyFile(testKeyFile, "")
	assert.EqualError(suite.T(), err, fmt.Sprintf("private key file %s doesn't exist", testKeyFile))

	// Test reading something that isn't a key
	_, err = readPrivateKeyFile(suite.testFile.Name(), "")
	assert.ErrorContains(suite.T(), err, fmt.Sprintf("file: %s", suite.testFile.Name()))

	// Test reading a public key
	_, err = readPrivateKeyFile(fmt.Sprintf("%s.pub.pem", testKeyFile), "")
	assert.ErrorContains(suite.T(), err, "private key format not supported")

	// Test reading a real key with wrong passphrase
	_, err = readPrivateKeyFile(fmt.Sprintf("%s.sec.pem", testKeyFile), "wrong")
	assert.ErrorContains(suite.T(), err, "chacha20poly1305: message authentication failed")

	// Test reading a real key
	_, err = readPrivateKeyFile(fmt.Sprintf("%s.sec.pem", testKeyFile), "test")
	assert.NoError(suite.T(), err)
}

func (suite *DecryptTests) Testdecrypt() {
	testKeyFile := filepath.Join(suite.tempDir, "testkey")
	encryptedFile := fmt.Sprintf("%s.c4gh", suite.testFile.Name())
	decryptedFile := filepath.Join(suite.tempDir, "decrypted_file")

	// generate key files
	err := createKey.GenerateKeyPair(testKeyFile, "")
	assert.NoError(suite.T(), err)
	// and read the private key
	privateKey, err := readPrivateKeyFile(fmt.Sprintf("%s.sec.pem", testKeyFile), "")
	assert.NoError(suite.T(), err)

	// Encrypt a file using the encrypt module. change to the test directory to
	// make sure that the checksum files end up there.
	cwd, err := os.Getwd()
	assert.NoError(suite.T(), err)
	err = os.Chdir(suite.tempDir)
	assert.NoError(suite.T(), err)
	encryptArgs := []string{"encrypt", "-key", fmt.Sprintf("%s.pub.pem", testKeyFile), suite.testFile.Name()}
	err = encrypt.Encrypt(encryptArgs)
	assert.NoError(suite.T(), err, "encrypting file for testing failed")
	err = os.Chdir(cwd)
	assert.NoError(suite.T(), err)

	// Test decrypting a non-existent file
	msg := "no such file or directory"
	if runtime.GOOS == "windows" {
		msg = "The system cannot find the file specified."
	}
	err = decryptFile(filepath.Join(suite.tempDir, "non-existent"), "output_file", *privateKey)
	assert.ErrorContains(suite.T(), err, msg)

	// Test decryption with malformed key
	fakeKey := [32]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	err = decryptFile(encryptedFile, decryptedFile, fakeKey)
	assert.EqualError(suite.T(), err, "could not create cryp4gh reader: could not find matching public key header, decryption failed")

	// Test decrypting with the real key
	err = decryptFile(encryptedFile, decryptedFile, *privateKey)
	assert.NoError(suite.T(), err)

	// Check content of the decrypted file
	inFile, err := os.Open(decryptedFile)
	assert.NoError(suite.T(), err, "unable to open decrypted file")
	fileData, err := io.ReadAll(inFile)
	assert.NoError(suite.T(), err, "unable to read decrypted file")
	assert.Equal(suite.T(), fileData, suite.fileContent)
}

func (suite *DecryptTests) TestDecrypt() {
	testKeyFile := filepath.Join(suite.tempDir, "testkey")
	err := createKey.GenerateKeyPair(testKeyFile, "")
	assert.NoError(suite.T(), err)

	// Encrypt a file using the encrypt module. change to the test directory to
	// make sure that the checksum files end up there.
	cwd, err := os.Getwd()
	assert.NoError(suite.T(), err)
	err = os.Chdir(suite.tempDir)
	assert.NoError(suite.T(), err)
	encryptArgs := []string{"encrypt", "-key", fmt.Sprintf("%s.pub.pem", testKeyFile), suite.testFile.Name()}
	assert.NoError(suite.T(), encrypt.Encrypt(encryptArgs), "encrypting file for testing failed")
	assert.NoError(suite.T(), os.Chdir(cwd))
	os.Setenv("C4GH_PASSWORD", "")
	if runtime.GOOS != "windows" {
		assert.NoError(suite.T(), os.Remove(suite.testFile.Name()))
		os.Args = []string{"decrypt", "-key", fmt.Sprintf("%s.sec.pem", testKeyFile), fmt.Sprintf("%s.c4gh", suite.testFile.Name())}
		err = Decrypt(os.Args)
		assert.NoError(suite.T(), err, "decrypt failed unexpectedly")

		// Check content of the decrypted file
		inFile, err := os.Open(suite.testFile.Name())
		assert.NoError(suite.T(), err, "unable to open decrypted file")
		fileData, err := io.ReadAll(inFile)
		assert.NoError(suite.T(), err, "unable to read decrypted file")
		assert.Equal(suite.T(), string(suite.fileContent), string(fileData))
	}

	os.Args = []string{"decrypt", "-key", fmt.Sprintf("%s.sec.pem", testKeyFile), "--force-overwrite", "--clean", fmt.Sprintf("%s.c4gh", suite.testFile.Name())}
	err = Decrypt(os.Args)
	assert.NoError(suite.T(), err, "decrypt failed unexpectedly")
	// Check that the encrypted file was removed
	_, err = os.Stat(fmt.Sprintf("%s.c4gh", suite.testFile.Name()))
	msg := "no such file or directory"
	if runtime.GOOS == "windows" {
		msg = "The system cannot find the file specified"
	}
	assert.ErrorContains(suite.T(), err, msg)
	// check that the decrypted file was created
	_, err = os.Stat(suite.testFile.Name())
	assert.NoError(suite.T(), err, "decrypted file was not created")
	os.Args = nil

}

func (suite *DecryptTests) TestDecryptMultipleFiles() {
	testKeyFile := filepath.Join(suite.tempDir, "testkey")
	err := createKey.GenerateKeyPair(testKeyFile, "")
	assert.NoError(suite.T(), err)

	// Setup files for encryption
	fileNames := []string{
		filepath.Join(suite.tempDir, "file1.txt"),
		filepath.Join(suite.tempDir, "file2.txt"),
		filepath.Join(suite.tempDir, "file3.txt"),
	}
	encryptedFiles := []string{
		filepath.Join(suite.tempDir, "file1.txt.c4gh"),
		filepath.Join(suite.tempDir, "file2.txt.c4gh"),
		filepath.Join(suite.tempDir, "file3.txt.c4gh"),
	}

	// Create and write to files
	for _, fileName := range fileNames {
		err := os.WriteFile(fileName, suite.fileContent, 0600)
		assert.NoError(suite.T(), err)
	}

	// Encrypt the files
	cwd, err := os.Getwd()
	assert.NoError(suite.T(), err)
	err = os.Chdir(suite.tempDir)
	assert.NoError(suite.T(), err)
	encryptArgs := []string{"encrypt", "-key", fmt.Sprintf("%s.pub.pem", testKeyFile)}
	for _, fileName := range fileNames {
		err = encrypt.Encrypt(append(encryptArgs, fileName))
		assert.NoError(suite.T(), err)
	}
	err = os.Chdir(cwd)
	assert.NoError(suite.T(), err)

	// Remove file2.txt and file3.txt to simulate their absence
	err = os.Remove(fileNames[1]) // file2.txt
	assert.NoError(suite.T(), err)

	err = os.Remove(fileNames[2]) // file3.txt
	assert.NoError(suite.T(), err)

	// Attempt to decrypt all files: file1.txt.c4gh will be skipped due to
	// existance of file1.txt, file2.txt.c4gh and file3.txt.c4gh will be
	// decrypted successfully, despite a non existing file in the list
	os.Setenv("C4GH_PASSWORD", "")
	os.Args = []string{"decrypt", "-key", fmt.Sprintf("%s.sec.pem", testKeyFile),
		encryptedFiles[0], encryptedFiles[1], "nonexistent_file.c4gh", encryptedFiles[2]}

	err = Decrypt(os.Args)
	assert.NoError(suite.T(), err, "decrypt failed unexpectedly")

	// Check the decrypted files
	for _, fileName := range fileNames[1:] { // Check file2.txt and file3.txt
		decryptedFile := filepath.Join(suite.tempDir, filepath.Base(fileName))

		// Verify that the file exists
		if _, err := os.Stat(decryptedFile); os.IsNotExist(err) {
			suite.T().Errorf("Decrypted file %s does not exist", decryptedFile)

			continue
		}

		// Open and read the decrypted file
		inFile, err := os.Open(decryptedFile)
		assert.NoError(suite.T(), err, "unable to open decrypted file")
		fileData, err := io.ReadAll(inFile)
		assert.NoError(suite.T(), err, "unable to read decrypted file")

		// Check the file content
		assert.Equal(suite.T(), fileData, suite.fileContent, "content of decrypted file does not match expected")
	}

	// Test decryption of multiple files with --force-overwrite enabled
	// First, modify the content of the decrypted files to ensure we can verify that they are overwritten later
	for _, fileName := range fileNames {
		decryptedFile := filepath.Join(suite.tempDir, filepath.Base(fileName))

		// Clear the file content by truncating the file
		err := os.WriteFile(decryptedFile, []byte{}, 0600)
		assert.NoError(suite.T(), err, "failed to empty the file content")
	}

	// Now, run decryption again with --force-overwrite enabled
	os.Args = []string{"decrypt", "-key", fmt.Sprintf("%s.sec.pem", testKeyFile), "--force-overwrite", encryptedFiles[0], encryptedFiles[1], encryptedFiles[2]}

	err = Decrypt(os.Args)
	assert.NoError(suite.T(), err, "decrypt with --force-overwrite failed unexpectedly")

	// Verify that all files have been overwritten
	for _, fileName := range fileNames { // Check all files
		decryptedFile := filepath.Join(suite.tempDir, filepath.Base(fileName))

		// Verify that the file exists
		if _, err := os.Stat(decryptedFile); os.IsNotExist(err) {
			suite.T().Errorf("Decrypted file %s does not exist after --force-overwrite", decryptedFile)

			continue
		}

		// Open and read the overwritten decrypted file
		inFile, err := os.Open(decryptedFile)
		assert.NoError(suite.T(), err, "unable to open overwritten decrypted file")
		fileData, err := io.ReadAll(inFile)
		assert.NoError(suite.T(), err, "unable to read overwritten decrypted file")

		// Check the file content to verify it has been overwritten
		assert.Equal(suite.T(), fileData, suite.fileContent, "content of overwritten file does not match expected")
	}

	// Cleanup
	os.Args = nil
}
