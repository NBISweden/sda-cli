package decrypt

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type DecryptTests struct {
	suite.Suite
	tempDir  string
	testFile *os.File
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

	// create an existing test file with some known content
	suite.testFile, err = ioutil.TempFile(suite.tempDir, "testfile-")
	if err != nil {
		log.Fatal("cannot create temporary public key file", err)
	}

	err = ioutil.WriteFile(suite.testFile.Name(), []byte("content"), 0600)
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
