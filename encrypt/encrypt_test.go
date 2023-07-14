package encrypt

import (
	"fmt"
	"log"
	"os"
	"runtime"
	"strings"
	"testing"

	"github.com/NBISweden/sda-cli/helpers"
	"github.com/neicnordic/crypt4gh/keys"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type EncryptTests struct {
	suite.Suite
	tempDir        string
	publicKey      *os.File
	privateKey     *os.File
	fileOk         *os.File
	encryptedFile  *os.File
	pubKeyData     [32]byte
	secKeyData     [32]byte
	multiPublicKey *os.File
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
	suite.tempDir, err = os.MkdirTemp(os.TempDir(), "sda-cli-test-")
	if err != nil {
		log.Fatal("Couldn't create temporary test directory", err)
	}

	// Write the keys to temporary files
	suite.publicKey, err = os.CreateTemp(suite.tempDir, "pubkey-")
	if err != nil {
		log.Fatal("Cannot create temporary public key file", err)
	}

	err = keys.WriteCrypt4GHX25519PublicKey(suite.publicKey, suite.pubKeyData)
	if err != nil {
		log.Fatalf("failed to write temporary public key file, %v", err)
	}

	suite.privateKey, err = os.CreateTemp(suite.tempDir, "seckey-")
	if err != nil {
		log.Fatal("cannot create temporary private key file", err)
	}

	err = keys.WriteCrypt4GHX25519PrivateKey(suite.privateKey, suite.secKeyData, []byte(""))
	if err != nil {
		log.Fatalf("failed to write temporary private key file, %v", err)
	}

	// Create temp file with concatenated pub keys.
	// Append same key twice. Works until we decide that we do not allow duplicates.
	suite.multiPublicKey, err = os.CreateTemp(suite.tempDir, "pubkey-")
	if err != nil {
		log.Fatal("Cannot create temporary public key file", err)
	}

	input, err := os.ReadFile(suite.publicKey.Name())
	if err != nil {
		log.Fatal("Cannot read from public key file", err)
	}

	err = os.WriteFile(suite.multiPublicKey.Name(), append(input, input...), 0600)
	if err != nil {
		log.Fatal("cannot write to temporary multi-key file", err)
	}

	// create an existing test file with some known content
	suite.fileOk, err = os.CreateTemp(suite.tempDir, "testfile-")
	if err != nil {
		log.Fatal("cannot create temporary public key file", err)
	}

	err = os.WriteFile(suite.fileOk.Name(), []byte("content"), 0600)
	if err != nil {
		log.Fatalf("failed to write to testfile: %s", err)
	}

	// create an existing encrypted test file
	suite.encryptedFile, err = os.CreateTemp(suite.tempDir, "encrypted-input")
	if err != nil {
		log.Fatal("cannot create temporary encrypted testfile", err)
	}

	err = os.WriteFile(suite.encryptedFile.Name(), []byte("crypt4gh"), 0600)
	if err != nil {
		log.Fatalf("failed to write to temporary encrypted testfile: %s", err)
	}
}

func (suite *EncryptTests) TearDownTest() {
	os.Remove(suite.publicKey.Name())
	os.Remove(suite.privateKey.Name())
	os.Remove(suite.multiPublicKey.Name())
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
	assert.EqualError(suite.T(), err, fmt.Sprintf("outfile %s already exists", suite.fileOk.Name()))

	// unencrypted isn't readable
	testNoUnencrypted := helpers.EncryptionFileSet{Unencrypted: "does-not-exist", Encrypted: suite.fileOk.Name()}
	err = checkFiles([]helpers.EncryptionFileSet{testNoUnencrypted})
	assert.EqualError(suite.T(), err, "cannot read input file does-not-exist")

	// Encrypted file is given as input
	verifyUnencrypted := helpers.EncryptionFileSet{Unencrypted: suite.encryptedFile.Name(), Encrypted: "does-not-exist"}
	err = checkFiles([]helpers.EncryptionFileSet{verifyUnencrypted})
	assert.EqualError(suite.T(), err, fmt.Sprintf("input file %s is already encrypted(.c4gh)", suite.encryptedFile.Name()))

}

func (suite *EncryptTests) TestreadPublicKey() {
	file, err := os.Open(suite.publicKey.Name())
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()
	publicKey, err := readPublicKey(file)
	assert.NoError(suite.T(), err)
	suite.Equal(publicKey, suite.pubKeyData)

	malformedKey := "-----BEGIN CRYPT4GH PUBLIC KEY-----\nvery bad\n-----END CRYPT4GH PUBLIC KEY-----"
	badFile := strings.NewReader(malformedKey)
	_, err = readPublicKey(badFile)
	assert.EqualError(suite.T(), err, "malformed key file")
}

func (suite *EncryptTests) TestreadPublicKeyFile() {
	publicKey, err := readPublicKeyFile(suite.publicKey.Name())
	assert.NoError(suite.T(), err)
	suite.Equal(*publicKey, suite.pubKeyData)
}

func (suite *EncryptTests) TestreadMultiPublicKeyFile() {
	specs := newKeySpecs()
	publicKey, err := readMultiPublicKeyFile(suite.multiPublicKey.Name(), specs)
	assert.NoError(suite.T(), err)
	b := *publicKey
	suite.Equal(b[0], suite.pubKeyData)
	suite.Equal(b[1], suite.pubKeyData)
}

func (suite *EncryptTests) TestcheckKeyFile() {
	specs := newKeySpecs()
	// file that contains key(s) in valid format
	size, err := checkKeyFile(suite.multiPublicKey.Name(), specs)
	assert.NoError(suite.T(), err)
	suite.Equal(size, int64(230))

	// file that does not contain a key in valid format
	size, err = checkKeyFile(suite.fileOk.Name(), specs)
	assert.ErrorContains(suite.T(), err, "invalid key format in file:")
	suite.Equal(size, int64(0))
}

func (suite *EncryptTests) TestcalculateHashes() {
	// unencrypted file doesn't exist
	msg := "open no-unencrypted: no such file or directory"
	if runtime.GOOS == "windows" {
		msg = "open no-unencrypted: The system cannot find the file specified."
	}
	testNoUnencrypted := helpers.EncryptionFileSet{Unencrypted: "no-unencrypted", Encrypted: suite.fileOk.Name()}
	_, err := calculateHashes(testNoUnencrypted)
	assert.EqualError(suite.T(), err, msg)

	// encrypted file doesn't exist
	msg = "open no-encrypted: no such file or directory"
	if runtime.GOOS == "windows" {
		msg = "open no-encrypted: The system cannot find the file specified."
	}
	testNoEncrypted := helpers.EncryptionFileSet{Unencrypted: suite.fileOk.Name(), Encrypted: "no-encrypted"}
	_, err = calculateHashes(testNoEncrypted)
	assert.EqualError(suite.T(), err, msg)

	// encrypted file doesn't exist
	testFileOk := helpers.EncryptionFileSet{Unencrypted: suite.fileOk.Name(), Encrypted: suite.fileOk.Name()}
	hashes, err := calculateHashes(testFileOk)
	assert.NoError(suite.T(), err)
	suite.Equal(hashes.unencryptedMd5, "9a0364b9e99bb480dd25e1f0284c8555")
	suite.Equal(hashes.unencryptedSha256, "ed7002b439e9ac845f22357d822bac1444730fbdb6016d3ec9432297b9ec9f73")
	suite.Equal(hashes.encryptedMd5, "9a0364b9e99bb480dd25e1f0284c8555")
	suite.Equal(hashes.encryptedSha256, "ed7002b439e9ac845f22357d822bac1444730fbdb6016d3ec9432297b9ec9f73")
}

func (suite *EncryptTests) TestEncryptFunction() {
	// pub key not given
	os.Args = []string{"encrypt", suite.fileOk.Name()}
	err := Encrypt(os.Args)
	assert.EqualError(suite.T(), err, "public key not provided, details: configuration file (.sda-cli-session) not found")

	// no such pub key file
	msg := "open somekey: no such file or directory"
	if runtime.GOOS == "windows" {
		msg = "open somekey: The system cannot find the file specified."
	}
	os.Args = []string{"encrypt", "-key", "somekey", suite.fileOk.Name()}
	err = Encrypt(os.Args)
	assert.EqualError(suite.T(), err, msg)
}
