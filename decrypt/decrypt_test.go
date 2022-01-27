package decrypt

import (
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"testing"

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
	suite.tempDir, err = ioutil.TempDir(os.TempDir(), "sda-cli-test-")
	if err != nil {
		log.Fatal("Couldn't create temporary test directory", err)
	}

	// create a test file...
	suite.testFile, err = ioutil.TempFile(suite.tempDir, "testfile-")
	if err != nil {
		log.Fatal("cannot create temporary public key file", err)
	}

	// ... create some content ...
	suite.fileContent = []byte("This is some fine content right here.")

	// ... and write the known content to it
	err = ioutil.WriteFile(suite.testFile.Name(), suite.fileContent, 0600)
	if err != nil {
		log.Fatalf("failed to write to testfile: %s", err)
	}
}

func (suite *DecryptTests) TearDownTest() {
	os.Remove(suite.tempDir)
}

func (suite *DecryptTests) TestgenerateKeyPair() {

	testFileName := filepath.Join(suite.tempDir, "keyfile")

	// none of the target files exist
	err := generateKeyPair(testFileName, "")
	assert.NoError(suite.T(), err)

	// now the targets exist - should crash on public-key existing
	err = generateKeyPair(testFileName, "")
	assert.EqualError(suite.T(), err, fmt.Sprintf("public key file %s.pub.pem already exists", testFileName))

	// remove the public key to test the private key exists error
	os.Remove(fmt.Sprintf("%s.pub.pem", testFileName))
	err = generateKeyPair(testFileName, "")
	assert.EqualError(suite.T(), err, fmt.Sprintf("private key file %s.sec.pem already exists", testFileName))

	// remove the private key just in case it would mess with other tests
	os.Remove(fmt.Sprintf("%s.sec.pem", testFileName))
}

func (suite *DecryptTests) TestreadPrivateKey() {

	testKeyFile := filepath.Join(suite.tempDir, "testkey")

	// generate key files
	err := generateKeyPair(testKeyFile, "")
	if err != nil {
		log.Fatalf("couldn't generate testing key pair: %s", err)
	}

	// Test reading a non-existent key
	_, err = readPrivateKey(testKeyFile, "")
	assert.EqualError(suite.T(), err, fmt.Sprintf("private key file %s doesn't exist", testKeyFile))

	// Test reading something that isn't a key
	_, err = readPrivateKey(suite.testFile.Name(), "")
	assert.EqualError(suite.T(), err, fmt.Sprintf("malformed key file: %s", suite.testFile.Name()))

	// Test reading a real key
	_, err = readPrivateKey(fmt.Sprintf("%s.sec.pem", testKeyFile), "")
	assert.NoError(suite.T(), err)
}

func (suite *DecryptTests) Testdecrypt() {

	testKeyFile := filepath.Join(suite.tempDir, "testkey")
	encryptedFile := fmt.Sprintf("%s.c4gh", suite.testFile.Name())
	decryptedFile := filepath.Join(suite.tempDir, "decrypted_file")

	// generate key files
	err := generateKeyPair(testKeyFile, "")
	if err != nil {
		log.Fatalf("couldn't generate testing key pair: %s", err)
	}
	// and read the private key
	privateKey, err := readPrivateKey(fmt.Sprintf("%s.sec.pem", testKeyFile), "")
	if err != nil {
		log.Fatalf("couldn't read test key: %s", err)
	}

	// Encrypt a file using the encrypt module. change to the test directory to
	// make sure that the checksum files end up there.
	cwd, err := os.Getwd()
	if err != nil {
		log.Fatal("could not get working directory")
	}
	err = os.Chdir(suite.tempDir)
	if err != nil {
		log.Fatal("could not change into test directory")
	}
	encryptArgs := []string{"-key", fmt.Sprintf("%s.pub.pem", testKeyFile), suite.testFile.Name()}
	err = encrypt.Encrypt(encryptArgs)
	if err != nil {
		log.Fatalf("couldn't encrypt file for decryption test: %s", err)
	}
	err = os.Chdir(cwd)
	if err != nil {
		log.Fatal("could not return from test directory")
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
		log.Fatalf("Couldn't open decrypted file %s for content checking", decryptedFile)
	}
	fileData, err := io.ReadAll(inFile)
	if err != nil {
		log.Fatal("Couldn't read decrypted filedata for content checking")
	}
	assert.Equal(suite.T(), fileData, suite.fileContent)
}
