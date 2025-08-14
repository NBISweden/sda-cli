package encrypt

import (
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"testing"

	"github.com/NBISweden/sda-cli/decrypt"
	"github.com/NBISweden/sda-cli/helpers"
	"github.com/NBISweden/sda-cli/login"
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
	largeFile      *os.File
}

func TestEncryptTestSuite(t *testing.T) {
	suite.Run(t, new(EncryptTests))
}

func (suite *EncryptTests) SetupTest() {
	var err error

	// Generate a crypt4gh key pair
	suite.pubKeyData, suite.secKeyData, err = keys.GenerateKeyPair()
	if err != nil {
		fmt.Fprintln(os.Stderr, "Couldn't generate key pair", err)
		os.Exit(1)
	}

	// Create a temporary directory for our files
	suite.tempDir, err = os.MkdirTemp(os.TempDir(), "sda-cli-test-")
	if err != nil {
		fmt.Fprintln(os.Stderr, "Couldn't create temporary test directory", err)
		os.Exit(1)
	}

	// Write the keys to temporary files
	suite.publicKey, err = os.CreateTemp(suite.tempDir, "pubkey-")
	if err != nil {
		fmt.Fprintln(os.Stderr, "Cannot create temporary public key file", err)
		os.Exit(1)
	}

	err = keys.WriteCrypt4GHX25519PublicKey(suite.publicKey, suite.pubKeyData)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to write temporary public key file, %v\n", err)
		os.Exit(1)
	}

	suite.privateKey, err = os.CreateTemp(suite.tempDir, "seckey-")
	if err != nil {
		fmt.Fprintln(os.Stderr, "cannot create temporary private key file", err)
		os.Exit(1)
	}

	err = keys.WriteCrypt4GHX25519PrivateKey(suite.privateKey, suite.secKeyData, []byte(""))
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to write temporary private key file, %v\n", err)
		os.Exit(1)
	}

	// Create temp file with concatenated pub keys.
	// Append same key twice. Works until we decide that we do not allow duplicates.
	suite.multiPublicKey, err = os.CreateTemp(suite.tempDir, "pubkey-")
	if err != nil {
		fmt.Fprintln(os.Stderr, "Cannot create temporary public key file", err)
		os.Exit(1)
	}

	input, err := os.ReadFile(suite.publicKey.Name())
	if err != nil {
		fmt.Fprintln(os.Stderr, "Cannot read from public key file", err)
		os.Exit(1)
	}

	err = os.WriteFile(suite.multiPublicKey.Name(), append(input, input...), 0600)
	if err != nil {
		fmt.Fprintln(os.Stderr, "cannot write to temporary multi-key file", err)
		os.Exit(1)
	}

	// create an existing test file with some known content
	suite.fileOk, err = os.CreateTemp(suite.tempDir, "testfile-")
	if err != nil {
		fmt.Fprintln(os.Stderr, "cannot create temporary public key file", err)
		os.Exit(1)
	}

	err = os.WriteFile(suite.fileOk.Name(), []byte("content"), 0600)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to write to testfile: %s\n", err)
		os.Exit(1)
	}

	// create an existing encrypted test file
	suite.encryptedFile, err = os.CreateTemp(suite.tempDir, "encrypted-input")
	if err != nil {
		fmt.Fprintln(os.Stderr, "cannot create temporary encrypted testfile", err)
		os.Exit(1)
	}

	err = os.WriteFile(suite.encryptedFile.Name(), []byte("crypt4gh"), 0600)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to write to temporary encrypted testfile: %s\n", err)
		os.Exit(1)
	}

	// create an large test file with some known content
	suite.largeFile, err = os.CreateTemp(suite.tempDir, "largefile-")
	if err != nil {
		fmt.Fprintln(os.Stderr, "cannot create temporary test file", err)
		os.Exit(1)
	}

	for range 2 * 1024 * 1024 {
		if _, e := suite.largeFile.WriteString("a"); e != nil {
			suite.FailNow("failed to write large file")
		}
	}
}

func (suite *EncryptTests) TearDownTest() {
	os.Remove("checksum_encrypted.md5")      //nolint:errcheck
	os.Remove("checksum_encrypted.sha256")   //nolint:errcheck
	os.Remove("checksum_unencrypted.md5")    //nolint:errcheck
	os.Remove("checksum_unencrypted.sha256") //nolint:errcheck
	os.RemoveAll(suite.tempDir)              //nolint:errcheck
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

func (suite *EncryptTests) TestreadPublicKeyFile() {
	file, err := os.Open(suite.publicKey.Name())
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer file.Close() //nolint:errcheck
	publicKey, err := readPublicKeyFile(file.Name())
	assert.NoError(suite.T(), err)
	suite.Equal(*publicKey, suite.pubKeyData)

	_, err = readPublicKeyFile(suite.fileOk.Name())
	assert.ErrorContains(suite.T(), err, fmt.Sprintf("file: %s", suite.fileOk.Name()))
}

func (suite *EncryptTests) TestreadMultiPublicKeyFile() {
	specs := newKeySpecs()
	publicKey, err := readMultiPublicKeyFile(suite.multiPublicKey.Name(), specs)
	assert.NoError(suite.T(), err)
	b := *publicKey
	suite.Equal(b[0], suite.pubKeyData)
	suite.Equal(b[1], suite.pubKeyData)

	_, err = readMultiPublicKeyFile(suite.fileOk.Name(), specs)
	assert.EqualError(suite.T(), err, fmt.Sprintf("no public keys found in file: %s", suite.fileOk.Name()))
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
	assert.EqualError(suite.T(), err, "configuration file (.sda-cli-session) not found")

	// no such pub key file
	msg := "open somekey: no such file or directory"
	if runtime.GOOS == "windows" {
		msg = "open somekey: The system cannot find the file specified."
	}
	os.Args = []string{"encrypt", "-key", "somekey", suite.fileOk.Name()}
	err = Encrypt(os.Args)
	assert.EqualError(suite.T(), err, msg)
}

func (suite *EncryptTests) TestPubKeyFromInfo() {
	publicKeyFileList = nil
	keyData, err := os.ReadFile(suite.publicKey.Name())
	if err != nil {
		suite.FailNow("failed to read public key from disk")
	}

	infoData := login.AuthInfo{
		PublicKey: base64.StdEncoding.EncodeToString(keyData),
	}
	responseData, err := json.Marshal(infoData)
	if err != nil {
		suite.FailNow("failed to marshal JSON response")
	}

	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(responseData)
	}))
	defer mockServer.Close()

	os.Args = []string{"encrypt", "-target", mockServer.URL, suite.fileOk.Name()}
	assert.NoError(suite.T(), Encrypt(os.Args), "Encrypt from info failed unexpectedly")

	os.Setenv("C4GH_PASSWORD", "") //nolint:errcheck
	if runtime.GOOS != "windows" {
		// verify that the file can be decrypted
		os.Remove(suite.fileOk.Name()) //nolint:errcheck
		os.Args = []string{"decrypt", "-key", suite.privateKey.Name(), fmt.Sprintf("%s.c4gh", suite.fileOk.Name())}
		assert.NoError(suite.T(), decrypt.Decrypt(os.Args), "decrypting encrypted file failed unexpectedly")
	}

	os.Args = []string{"decrypt", "-key", suite.privateKey.Name(), "--force-overwrite", fmt.Sprintf("%s.c4gh", suite.fileOk.Name())}
	assert.NoError(suite.T(), decrypt.Decrypt(os.Args), "decrypting encrypted file failed unexpectedly")
}
func (suite *EncryptTests) TestStream() {
	md5 := md5.New()

	file, err := os.Open(suite.fileOk.Name())
	assert.NoError(suite.T(), err, "opening file failed unexpectedly")

	fs, err := Stream(file, [][32]byte{suite.pubKeyData})
	assert.NoError(suite.T(), err, "failed to create encryption stream")
	// make sure that no data is being read in order to save on memory
	assert.Equal(suite.T(), hex.EncodeToString(md5.Sum(nil)), hex.EncodeToString(fs.UnencryptedMD5.Sum(nil)))

	enc, err := io.ReadAll(fs.Reader)
	assert.NoError(suite.T(), err, "failed to read from encryption stream")
	assert.Equal(suite.T(), "crypt4gh", string(enc[:8]))
	md5.Write([]byte("content"))
	// ensure that the MD5 is what we expect it to be after the file has been read fully.
	assert.Equal(suite.T(), hex.EncodeToString(md5.Sum(nil)), hex.EncodeToString(fs.UnencryptedMD5.Sum(nil)))

	_ = file.Close()
}
func (suite *EncryptTests) TestStream_largeFile() {
	md5 := md5.New()

	file, err := os.Open(suite.largeFile.Name())
	assert.NoError(suite.T(), err, "opening file failed unexpectedly")
	info, _ := file.Stat()
	assert.Equal(suite.T(), int64(2*1024*1024), info.Size())

	fs, err := Stream(file, [][32]byte{suite.pubKeyData})
	assert.NoError(suite.T(), err, "failed to create encryption stream")
	// make sure that no data is being read in order to save on memory
	assert.Equal(suite.T(), hex.EncodeToString(md5.Sum(nil)), hex.EncodeToString(fs.UnencryptedMD5.Sum(nil)))

	enc, err := io.ReadAll(fs.Reader)
	assert.NoError(suite.T(), err, "failed to read from encryption stream")
	_ = fs.Reader.Close()
	_ = file.Close()

	assert.Equal(suite.T(), "crypt4gh", string(enc[:8]))
	assert.Greater(suite.T(), len(enc), 2*1024*1024)
	assert.Equal(suite.T(), 2098172, len(enc))
	// ensure that the MD5 is what we expect it to be after the file has been read fully.
	assert.Equal(suite.T(), "de89461b64701958984c95d1bfb0065a", hex.EncodeToString(fs.UnencryptedMD5.Sum(nil)))

	// f, err := os.Create(fmt.Sprintf("%s/largefile2.c4gh", suite.tempDir))
	f, err := os.Create(fmt.Sprintf("%s/largefile2.c4gh", suite.tempDir))
	assert.NoError(suite.T(), err, "failed to create temp file")
	n, err := f.Write(enc)
	assert.NoError(suite.T(), err, "failed write data to temp file")
	assert.Equal(suite.T(), 2098172, n)
	_ = f.Close()

	os.Setenv("C4GH_PASSWORD", "") //nolint:errcheck
	os.Args = []string{"decrypt", "-key", suite.privateKey.Name(), "--force-overwrite", f.Name()}
	suite.T().Log(os.Args)
	assert.NoError(suite.T(), decrypt.Decrypt(os.Args), "decrypting encrypted file failed unexpectedly")
}
func (suite *EncryptTests) TestStream_noPublicKey() {
	var file *os.File
	_, err := Stream(file, [][32]byte{})
	assert.ErrorContains(suite.T(), err, "no public key supplied")
}
