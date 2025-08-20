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

type DecryptFileTestSuite struct {
	suite.Suite
	tempDir       string // The directory this test will take place in
	encryptedFile string
	fileContent   []byte
	testKeyFile   string
	privateKey    *[32]byte
}

func TestDecryptFileTestSuite(t *testing.T) {
	suite.Run(t, new(DecryptFileTestSuite))
}

func (suite *DecryptFileTestSuite) SetupTest() {
	suite.tempDir = suite.T().TempDir()

	suite.testKeyFile = filepath.Join(suite.tempDir, "testkey")

	err := createKey.GenerateKeyPair(suite.testKeyFile, "")
	if err != nil {
		suite.FailNow("failed to generate key pair", err)
	}
	os.Setenv("C4GH_PASSWORD", "")

	suite.privateKey, err = readPrivateKeyFile(fmt.Sprintf("%s.sec.pem", suite.testKeyFile), "")
	if err != nil {
		suite.FailNow("failed to read private key", err)
	}

	// create a test file...
	testFile, err := os.CreateTemp(suite.tempDir, "testfile-")
	if err != nil {
		suite.FailNow("failed to create test file in temporary directory", err)
	}
	suite.fileContent = []byte(fmt.Sprintf("This is some fine content right here, in file: %s", testFile.Name()))
	// ... and write the known content to it
	err = os.WriteFile(testFile.Name(), suite.fileContent, 0600)
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

	suite.encryptedFile = fmt.Sprintf("%s.c4gh", testFile.Name())
}

func (suite *DecryptFileTestSuite) TearDownTest() {
	// The temporary directory cleanup is managed by the testing library as documented
	// at https://pkg.go.dev/testing#T.TempDir
	_ = os.Remove("checksum_encrypted.md5")
	_ = os.Remove("checksum_unencrypted.md5")
	_ = os.Remove("checksum_encrypted.sha256")
	_ = os.Remove("checksum_unencrypted.sha256")
}

func (suite *DecryptFileTestSuite) TestDecryptFileSuccess() {
	decryptedFile := filepath.Join(suite.tempDir, "decrypted_file")

	err := decryptFile(suite.encryptedFile, decryptedFile, *suite.privateKey)
	assert.NoError(suite.T(), err)

	// Check content of the decrypted file
	inFile, err := os.Open(decryptedFile)
	assert.NoError(suite.T(), err, "unable to open decrypted file")
	fileData, err := io.ReadAll(inFile)
	_ = inFile.Close()
	assert.NoError(suite.T(), err, "unable to read decrypted file")
	assert.Equal(suite.T(), fileData, suite.fileContent)

}
func (suite *DecryptFileTestSuite) TestDecryptFileMalformedKey() {
	decryptedFile := filepath.Join(suite.tempDir, "decrypted_file")

	suite.privateKey = &[32]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}

	err := decryptFile(suite.encryptedFile, decryptedFile, *suite.privateKey)
	assert.EqualError(suite.T(), err, "could not create cryp4gh reader: could not find matching public key header, decryption failed")
}

func (suite *DecryptFileTestSuite) TestDecryptFileNonExistentFile() {
	msg := "no such file or directory"
	if runtime.GOOS == "windows" {
		msg = "The system cannot find the file specified."
	}
	err := decryptFile(filepath.Join(suite.tempDir, "non-existent"), "output_file", *suite.privateKey)
	assert.ErrorContains(suite.T(), err, msg)
}
