package encrypt

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"testing"

	"github.com/NBISweden/sda-cli/helpers"
	"github.com/elixir-oslo/crypt4gh/keys"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type EncryptTests struct {
	suite.Suite
	tempDir       string
	publicKey     *os.File
	privateKey    *os.File
	fileOk        *os.File
	encryptedFile *os.File
	pubKeyData    [32]byte
	secKeyData    [32]byte
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

	// create an existing encrypted test file
	suite.encryptedFile, err = ioutil.TempFile(suite.tempDir, "encrypted-input")
	if err != nil {
		log.Fatal("cannot create temporary encrypted testfile", err)
	}

	err = ioutil.WriteFile(suite.encryptedFile.Name(), []byte("crypt4gh"), 0600)
	if err != nil {
		log.Fatalf("failed to write to temporary encrypted testfile: %s", err)
	}
}

func (suite *EncryptTests) TearDownTest() {
	os.Remove(suite.publicKey.Name())
	os.Remove(suite.privateKey.Name())
	os.Remove(suite.fileOk.Name())
	os.Remove(suite.encryptedFile.Name())
	os.Remove(suite.tempDir)
}

func (suite *EncryptTests) TestcheckFiles() {
	// unencrypted is readable, and unencrypted isn't (this is fine!)
	testOk := helpers.EncryptionFileSet{Unencrypted: suite.fileOk.Name(), Encrypted: "does-not-exist"}
	err := checkFiles([]helpers.EncryptionFileSet{testOk})
	assert.NoError(suite.T(), err)

	// unencrypted is readable, but encrypted exists
	testHasEncrypted := helpers.EncryptionFileSet{Unencrypted: suite.fileOk.Name(), Encrypted: suite.fileOk.Name()}
	err = checkFiles([]helpers.EncryptionFileSet{testHasEncrypted})
	assert.EqualError(suite.T(), err, fmt.Sprintf("Outfile %s already exists", suite.fileOk.Name()))

	// unencrypted isn't readable
	testNoUnencrypted := helpers.EncryptionFileSet{Unencrypted: "does-not-exist", Encrypted: suite.fileOk.Name()}
	err = checkFiles([]helpers.EncryptionFileSet{testNoUnencrypted})
	assert.EqualError(suite.T(), err, "Cannot read input file does-not-exist")

	// Encrypted file is given as input
	verifyUnencrypted := helpers.EncryptionFileSet{Unencrypted: suite.encryptedFile.Name(), Encrypted: "does-not-exist"}
	err = checkFiles([]helpers.EncryptionFileSet{verifyUnencrypted})
	assert.EqualError(suite.T(), err, fmt.Sprintf("Input file %s is already encrypted(.c4gh) - make sure the right pk was used", suite.encryptedFile.Name()))

}

func (suite *EncryptTests) TestreadPublicKey() {
	publicKey, err := readPublicKey(suite.publicKey.Name())
	assert.NoError(suite.T(), err)
	suite.Equal(*publicKey, suite.pubKeyData)
}

func (suite *EncryptTests) TestcalculateHashes() {
	// unencrypted file doesn't exist
	testNoUnencrypted := helpers.EncryptionFileSet{Unencrypted: "no-unencrypted", Encrypted: suite.fileOk.Name()}
	_, err := calculateHashes(testNoUnencrypted)
	assert.EqualError(suite.T(), err, "open no-unencrypted: no such file or directory")

	// encrypted file doesn't exist
	testNoEncrypted := helpers.EncryptionFileSet{Unencrypted: suite.fileOk.Name(), Encrypted: "no-encrypted"}
	_, err = calculateHashes(testNoEncrypted)
	assert.EqualError(suite.T(), err, "open no-encrypted: no such file or directory")

	// encrypted file doesn't exist
	testFileOk := helpers.EncryptionFileSet{Unencrypted: suite.fileOk.Name(), Encrypted: suite.fileOk.Name()}
	hashes, err := calculateHashes(testFileOk)
	assert.NoError(suite.T(), err)
	suite.Equal(hashes.unencryptedMd5, "9a0364b9e99bb480dd25e1f0284c8555")
	suite.Equal(hashes.unencryptedSha256, "ed7002b439e9ac845f22357d822bac1444730fbdb6016d3ec9432297b9ec9f73")
	suite.Equal(hashes.encryptedMd5, "9a0364b9e99bb480dd25e1f0284c8555")
	suite.Equal(hashes.encryptedSha256, "ed7002b439e9ac845f22357d822bac1444730fbdb6016d3ec9432297b9ec9f73")
}
