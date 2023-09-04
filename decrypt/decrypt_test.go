package decrypt

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"

	createKey "github.com/NBISweden/sda-cli/create_key"
	"github.com/NBISweden/sda-cli/encrypt"
	"github.com/NBISweden/sda-cli/helpers"
	log "github.com/sirupsen/logrus"
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
	if err != nil {
		log.Error("Couldn't create temporary test directory", err)
	}

	// create a test file...
	suite.testFile, err = os.CreateTemp(suite.tempDir, "testfile-")
	if err != nil {
		log.Error("cannot create temporary public key file", err)
	}

	// ... create some content ...
	suite.fileContent = []byte("This is some fine content right here.")

	// ... and write the known content to it
	err = os.WriteFile(suite.testFile.Name(), suite.fileContent, 0600)
	if err != nil {
		log.Errorf("failed to write to testfile: %s", err)
	}
}

func (suite *DecryptTests) TearDownTest() {
	os.Remove(suite.tempDir)
}

func (suite *DecryptTests) TestreadPrivateKeyFile() {

	testKeyFile := filepath.Join(suite.tempDir, "testkey")

	// generate key files

	err := createKey.GenerateKeyPair(testKeyFile, "")
	if err != nil {
		log.Errorf("couldn't generate testing key pair: %s", err)
	}

	// Test reading a non-existent key
	_, err = readPrivateKeyFile(testKeyFile, "")
	assert.EqualError(suite.T(), err, fmt.Sprintf("private key file %s doesn't exist", testKeyFile))

	// Test reading something that isn't a key
	_, err = readPrivateKeyFile(suite.testFile.Name(), "")
	assert.ErrorContains(suite.T(), err, fmt.Sprintf("file: %s", suite.testFile.Name()))

	// Test reading a real key
	_, err = readPrivateKeyFile(fmt.Sprintf("%s.sec.pem", testKeyFile), "")
	assert.NoError(suite.T(), err)
}

func (suite *DecryptTests) TestcheckFiles() {
	// unencrypted is readable, and unencrypted isn't (this is fine!)
	testOk := helpers.EncryptionFileSet{Encrypted: suite.testFile.Name(), Unencrypted: "does-not-exist"}
	err := checkFiles([]helpers.EncryptionFileSet{testOk})
	assert.NoError(suite.T(), err)

	// unencrypted is readable, but encrypted exists
	testHasEncrypted := helpers.EncryptionFileSet{Encrypted: suite.testFile.Name(), Unencrypted: suite.testFile.Name()}
	err = checkFiles([]helpers.EncryptionFileSet{testHasEncrypted})
	assert.EqualError(suite.T(), err, fmt.Sprintf("outfile %s already exists",
		suite.testFile.Name()))

	// unencrypted isn't readable
	testNoUnencrypted := helpers.EncryptionFileSet{Encrypted: "does-not-exist", Unencrypted: suite.testFile.Name()}
	err = checkFiles([]helpers.EncryptionFileSet{testNoUnencrypted})
	assert.EqualError(suite.T(), err, "cannot read input file does-not-exist")
}

func (suite *DecryptTests) Testdecrypt() {

	testKeyFile := filepath.Join(suite.tempDir, "testkey")
	encryptedFile := fmt.Sprintf("%s.c4gh", suite.testFile.Name())
	decryptedFile := filepath.Join(suite.tempDir, "decrypted_file")

	// generate key files
	err := createKey.GenerateKeyPair(testKeyFile, "")
	if err != nil {
		log.Errorf("couldn't generate testing key pair: %s", err)
	}
	// and read the private key
	privateKey, err := readPrivateKeyFile(fmt.Sprintf("%s.sec.pem", testKeyFile), "")
	if err != nil {
		log.Errorf("couldn't read test key: %s", err)
	}

	// Encrypt a file using the encrypt module. change to the test directory to
	// make sure that the checksum files end up there.
	cwd, err := os.Getwd()
	if err != nil {
		log.Error("could not get working directory")
	}
	err = os.Chdir(suite.tempDir)
	if err != nil {
		log.Error("could not change into test directory")
	}
	encryptArgs := []string{"sda-cli", "-key", fmt.Sprintf("%s.pub.pem", testKeyFile), suite.testFile.Name()}
	err = encrypt.Encrypt(encryptArgs)
	if err != nil {
		log.Errorf("couldn't encrypt file for decryption test: %s", err)
	}
	err = os.Chdir(cwd)
	if err != nil {
		log.Error("could not return from test directory")
	}

	// Test decrypting a non-existent file
	err = decrypt(filepath.Join(suite.tempDir, "non-existent"), "output_file", *privateKey)
	assert.EqualError(suite.T(), err, fmt.Sprintf("infile %s does not exist or could not be read", filepath.Join(suite.tempDir, "non-existent")))

	// Test decrypting where the output file exists
	err = decrypt(encryptedFile, suite.testFile.Name(), *privateKey)
	assert.EqualError(suite.T(), err, fmt.Sprintf("outfile %s already exists", suite.testFile.Name()))

	// Test decryption with malformed key
	fakeKey := [32]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	err = decrypt(encryptedFile, decryptedFile, fakeKey)
	assert.EqualError(suite.T(), err, "could not create cryp4gh reader: could not find matching public key header, decryption failed")

	// Test decrypting with the real key
	err = decrypt(encryptedFile, decryptedFile, *privateKey)
	assert.NoError(suite.T(), err)

	// Check content of the decrypted file
	inFile, err := os.Open(decryptedFile)
	if err != nil {
		log.Errorf("Couldn't open decrypted file %s for content checking", decryptedFile)
	}
	fileData, err := io.ReadAll(inFile)
	if err != nil {
		log.Error("Couldn't read decrypted filedata for content checking")
	}
	assert.Equal(suite.T(), fileData, suite.fileContent)
}
