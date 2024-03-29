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

	os.Args = []string{"decrypt", "-key", fmt.Sprintf("%s.sec.pem", testKeyFile), "--force-overwrite", fmt.Sprintf("%s.c4gh", suite.testFile.Name())}
	err = Decrypt(os.Args)
	assert.NoError(suite.T(), err, "decrypt failed unexpectedly")
	os.Args = nil
}
