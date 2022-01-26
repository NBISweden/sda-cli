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
	temp_dir   string
	publicKey  *os.File
	privateKey *os.File
	file_ok    *os.File
	pubKeyData [32]byte
	secKeyData [32]byte
}

func TestEncryptTestSuite(t *testing.T) {
	suite.Run(t, new(EncryptTests))
}

func (suite *EncryptTests) SetupTest() {

	var err error = nil

	// Generate a crypt4gh key pair
	suite.pubKeyData, suite.secKeyData, err = keys.GenerateKeyPair()
	if err != nil {
		log.Fatal("Couldn't generate key pair", err)
	}

	// Create a temporary directory for our files
	suite.temp_dir, err = ioutil.TempDir(os.TempDir(), "sda-cli-test-")
	if err != nil {
		log.Fatal("Couldn't create temporary test directory", err)
	}

	// Write the keys to temporary files
	suite.publicKey, err = ioutil.TempFile(suite.temp_dir, "pubkey-")
	if err != nil {
		log.Fatal("Cannot create temporary public key file", err)
	}

	err = keys.WriteCrypt4GHX25519PublicKey(suite.publicKey, suite.pubKeyData)
	if err != nil {
		log.Fatalf("failed to write temporary public key file, %v", err)
	}

	suite.privateKey, err = ioutil.TempFile(suite.temp_dir, "seckey-")
	if err != nil {
		log.Fatal("cannot create temporary private key file", err)
	}

	err = keys.WriteCrypt4GHX25519PrivateKey(suite.privateKey, suite.secKeyData,
		[]byte(""))
	if err != nil {
		log.Fatalf("failed to write temporary private key file, %v", err)
	}

	// create an existing test file with some known content
	suite.file_ok, err = ioutil.TempFile(suite.temp_dir, "testfile-")
	if err != nil {
		log.Fatal("cannot create temporary public key file", err)
	}

	err = ioutil.WriteFile(suite.file_ok.Name(), []byte("content"), 0644)
	if err != nil {
		log.Fatalf("failed to write to testfile: %s", err)
	}
}

func (suite *EncryptTests) TearDownTest() {
	os.Remove(suite.publicKey.Name())
	os.Remove(suite.privateKey.Name())
	os.Remove(suite.file_ok.Name())
	os.Remove(suite.temp_dir)
}

func (suite *EncryptTests) TestcheckFiles() {
	// unencrypted is readable, and unencrypted isn't (this is fine!)
	test_ok := encryptionFileSet{suite.file_ok.Name(), "does-not-exist"}
	err := checkFiles([]encryptionFileSet{test_ok})
	assert.NoError(suite.T(), err)

	// unencrypted is readable, but encrypted exists
	test_has_encrypted := encryptionFileSet{suite.file_ok.Name(),
		suite.file_ok.Name()}
	err = checkFiles([]encryptionFileSet{test_has_encrypted})
	assert.EqualError(suite.T(), err, fmt.Sprintf("outfile %s already exists",
		suite.file_ok.Name()))

	// unencrypted isn't readable
	test_no_unencrypted := encryptionFileSet{"does-not-exist",
		suite.file_ok.Name()}
	err = checkFiles([]encryptionFileSet{test_no_unencrypted})
	assert.EqualError(suite.T(), err, "cannot read input file does-not-exist")
}

func (suite *EncryptTests) TestreadPublicKey() {
	publicKey, err := readPublicKey(suite.publicKey.Name())
	assert.NoError(suite.T(), err)
	suite.Equal(*publicKey, suite.pubKeyData)
}

func (suite *EncryptTests) TestcalculateHashes() {
	// unencrypted file doesn't exist
	test_no_unencrypted := encryptionFileSet{"no-unencrypted",
		suite.file_ok.Name()}
	_, err := calculateHashes(test_no_unencrypted)
	assert.EqualError(suite.T(), err,
		"open no-unencrypted: no such file or directory")

	// encrypted file doesn't exist
	test_no_encrypted := encryptionFileSet{suite.file_ok.Name(), "no-encrypted"}
	_, err = calculateHashes(test_no_encrypted)
	assert.EqualError(suite.T(), err,
		"open no-encrypted: no such file or directory")

	// encrypted file doesn't exist
	test_file_ok := encryptionFileSet{suite.file_ok.Name(),
		suite.file_ok.Name()}
	hashes, err := calculateHashes(test_file_ok)
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
	test_exists := FileExists(suite.file_ok.Name())
	suite.Equal(test_exists, true)
	// file does not exists
	test_missing := FileExists("does-not-exist")
	suite.Equal(test_missing, false)
	// file is a directory
	test_is_dir := FileExists(suite.temp_dir)
	suite.Equal(test_is_dir, true)
}

func (suite *EncryptTests) TestFileIsReadable() {
	// file doesn't exist
	test_missing := FileIsReadable("does-not-exist")
	suite.Equal(test_missing, false)

	// file is a directory
	test_is_dir := FileIsReadable(suite.temp_dir)
	suite.Equal(test_is_dir, false)

	// file can be read
	test_file_ok := FileIsReadable(suite.file_ok.Name())
	suite.Equal(test_file_ok, true)

	// test file permissions. This doesn't work on windows, so we do an extra
	// check to see if this test makes sense.
	if runtime.GOOS != "windows" {
		err := os.Chmod(suite.file_ok.Name(), 0000)
		if err != nil {
			log.Fatal("Couldn't set file permissions of test file")
		}
		// file permissions don't allow reading
		test_disallowed := FileIsReadable(suite.file_ok.Name())
		suite.Equal(test_disallowed, false)

		// restore permissions
		err = os.Chmod(suite.file_ok.Name(), 0644)
		if err != nil {
			log.Fatal("Couldn't restore file permissions of test file")
		}
	}
}
