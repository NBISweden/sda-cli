package encrypt

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"runtime"
	"testing"

	"github.com/elixir-oslo/crypt4gh/keys"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type EncryptTests struct {
	suite.Suite
	tempDir    string
	publicKey  *os.File
	privateKey *os.File
	fileOk     *os.File
	pubKeyData [32]byte
	secKeyData [32]byte
}

func TestEncryptTestSuite(t *testing.T) {
	suite.Run(t, new(EncryptTests))
}

func (suite *EncryptTests) SetupTest() {

	var err error

	// Generate a crypt4gh key pair
	suite.pubKeyData, suite.secKeyData, err = keys.GenerateKeyPair()
	if err != nil {
		log.Fatal("Couldn't generate key pair", err)
	}

	// Create a temporary directory for our files
	suite.tempDir, err = ioutil.TempDir(os.TempDir(), "sda-cli-test-")
	if err != nil {
		log.Fatal("Couldn't create temporary test directory", err)
	}

	// Write the keys to temporary files
	suite.publicKey, err = ioutil.TempFile(suite.tempDir, "pubkey-")
	if err != nil {
		log.Fatal("Cannot create temporary public key file", err)
	}

	err = keys.WriteCrypt4GHX25519PublicKey(suite.publicKey, suite.pubKeyData)
	if err != nil {
		log.Fatalf("failed to write temporary public key file, %v", err)
	}

	suite.privateKey, err = ioutil.TempFile(suite.tempDir, "seckey-")
	if err != nil {
		log.Fatal("cannot create temporary private key file", err)
	}

	err = keys.WriteCrypt4GHX25519PrivateKey(suite.privateKey, suite.secKeyData, []byte(""))
	if err != nil {
		log.Fatalf("failed to write temporary private key file, %v", err)
	}

	// create an existing test file with some known content
	suite.fileOk, err = ioutil.TempFile(suite.tempDir, "testfile-")
	if err != nil {
		log.Fatal("cannot create temporary public key file", err)
	}

	err = ioutil.WriteFile(suite.fileOk.Name(), []byte("content"), 0600)
	if err != nil {
		log.Fatalf("failed to write to testfile: %s", err)
	}
}

func (suite *EncryptTests) TearDownTest() {
	os.Remove(suite.publicKey.Name())
	os.Remove(suite.privateKey.Name())
	os.Remove(suite.fileOk.Name())
	os.Remove(suite.tempDir)
}

func (suite *EncryptTests) TestcheckFiles() {
	// unencrypted is readable, and unencrypted isn't (this is fine!)
	testOk := encryptionFileSet{suite.fileOk.Name(), "does-not-exist"}
	err := checkFiles([]encryptionFileSet{testOk})
	assert.NoError(suite.T(), err)

	// unencrypted is readable, but encrypted exists
	testHasEncrypted := encryptionFileSet{suite.fileOk.Name(),
		suite.fileOk.Name()}
	err = checkFiles([]encryptionFileSet{testHasEncrypted})
	assert.EqualError(suite.T(), err, fmt.Sprintf("outfile %s already exists",
		suite.fileOk.Name()))

	// unencrypted isn't readable
	testNoUnencrypted := encryptionFileSet{"does-not-exist",
		suite.fileOk.Name()}
	err = checkFiles([]encryptionFileSet{testNoUnencrypted})
	assert.EqualError(suite.T(), err, "cannot read input file does-not-exist")
}

func (suite *EncryptTests) TestreadPublicKey() {
	publicKey, err := readPublicKey(suite.publicKey.Name())
	assert.NoError(suite.T(), err)
	suite.Equal(*publicKey, suite.pubKeyData)
}

func (suite *EncryptTests) TestcalculateHashes() {
	// unencrypted file doesn't exist
	testNoUnencrypted := encryptionFileSet{"no-unencrypted",
		suite.fileOk.Name()}
	_, err := calculateHashes(testNoUnencrypted)
	assert.EqualError(suite.T(), err,
		"open no-unencrypted: no such file or directory")

	// encrypted file doesn't exist
	testNoEncrypted := encryptionFileSet{suite.fileOk.Name(), "no-encrypted"}
	_, err = calculateHashes(testNoEncrypted)
	assert.EqualError(suite.T(), err,
		"open no-encrypted: no such file or directory")

	// encrypted file doesn't exist
	testFileOk := encryptionFileSet{suite.fileOk.Name(),
		suite.fileOk.Name()}
	hashes, err := calculateHashes(testFileOk)
	assert.NoError(suite.T(), err)
	suite.Equal(hashes.unencryptedMd5, "9a0364b9e99bb480dd25e1f0284c8555")
	suite.Equal(hashes.unencryptedSha256,
		"ed7002b439e9ac845f22357d822bac1444730fbdb6016d3ec9432297b9ec9f73")
	suite.Equal(hashes.encryptedMd5, "9a0364b9e99bb480dd25e1f0284c8555")
	suite.Equal(hashes.encryptedSha256,
		"ed7002b439e9ac845f22357d822bac1444730fbdb6016d3ec9432297b9ec9f73")
}

func (suite *EncryptTests) TestFileExists() {
	// file exists
	testExists := FileExists(suite.fileOk.Name())
	suite.Equal(testExists, true)
	// file does not exists
	testMissing := FileExists("does-not-exist")
	suite.Equal(testMissing, false)
	// file is a directory
	testIsDir := FileExists(suite.tempDir)
	suite.Equal(testIsDir, true)
}

func (suite *EncryptTests) TestFileIsReadable() {
	// file doesn't exist
	testMissing := FileIsReadable("does-not-exist")
	suite.Equal(testMissing, false)

	// file is a directory
	testIsDir := FileIsReadable(suite.tempDir)
	suite.Equal(testIsDir, false)

	// file can be read
	testFileOk := FileIsReadable(suite.fileOk.Name())
	suite.Equal(testFileOk, true)

	// test file permissions. This doesn't work on windows, so we do an extra
	// check to see if this test makes sense.
	if runtime.GOOS != "windows" {
		err := os.Chmod(suite.fileOk.Name(), 0000)
		if err != nil {
			log.Fatal("Couldn't set file permissions of test file")
		}
		// file permissions don't allow reading
		testDisallowed := FileIsReadable(suite.fileOk.Name())
		suite.Equal(testDisallowed, false)

		// restore permissions
		err = os.Chmod(suite.fileOk.Name(), 0600)
		if err != nil {
			log.Fatal("Couldn't restore file permissions of test file")
		}
	}
}
