package encrypt

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"testing"

	"github.com/NBISweden/sda-cli/decrypt"
	"github.com/neicnordic/crypt4gh/keys"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type EncryptStreamTestSuite struct {
	suite.Suite
	tempDir            string
	pubKeyData         [32]byte
	publicKey          *os.File
	privateKey         *os.File
	fileToEncrypt      *os.File
	largeFileToEncrypt *os.File
}

func TestEncryptStreamTestSuite(t *testing.T) {
	suite.Run(t, new(EncryptStreamTestSuite))
}

func (suite *EncryptStreamTestSuite) SetupTest() {
	// Create a temporary directory for our files
	suite.tempDir = suite.T().TempDir()

	var err error

	// Generate a crypt4gh key pair
	var secKeyData [32]byte
	suite.pubKeyData, secKeyData, err = keys.GenerateKeyPair()
	if err != nil {
		suite.FailNow("failed to generate key pair", err)
	}

	// Write the keys to temporary files
	suite.publicKey, err = os.CreateTemp(suite.tempDir, "pubkey-")
	if err != nil {
		suite.FailNow("failed to create temp public key test file", err)
	}

	if err = keys.WriteCrypt4GHX25519PublicKey(suite.publicKey, suite.pubKeyData); err != nil {
		suite.FailNow("failed to write to public key test file", err)
	}
	_ = suite.publicKey.Close()

	suite.privateKey, err = os.CreateTemp(suite.tempDir, "seckey-")
	if err != nil {
		suite.FailNow("failed to create temp private key test file", err)
	}

	err = keys.WriteCrypt4GHX25519PrivateKey(suite.privateKey, secKeyData, []byte(""))
	if err != nil {
		suite.FailNow("failed to write to private key", err)
	}
	_ = suite.privateKey.Close()

	// create an existing test file with some known content
	suite.fileToEncrypt, err = os.CreateTemp(suite.tempDir, "testfile-")
	if err != nil {
		suite.FailNow("failed to create test file", err)
	}

	err = os.WriteFile(suite.fileToEncrypt.Name(), []byte("content"), 0600)
	if err != nil {
		suite.FailNow("failed to write to test file", err)
	}
	_ = suite.fileToEncrypt.Close()

	// create an large test file with some known content
	suite.largeFileToEncrypt, err = os.CreateTemp(suite.tempDir, "largefile-")
	if err != nil {
		suite.FailNow("failed to create largefile test file", err)
	}

	for range 2 * 1024 * 1024 {
		if _, err = suite.largeFileToEncrypt.WriteString("a"); err != nil {
			suite.FailNow("failed to write largefile test file", err)
		}
	}
	_ = suite.largeFileToEncrypt.Close()
}

func (suite *EncryptStreamTestSuite) TearDownTest() {
	_ = os.Remove("checksum_encrypted.md5")
	_ = os.Remove("checksum_encrypted.sha256")
	_ = os.Remove("checksum_unencrypted.md5")
	_ = os.Remove("checksum_unencrypted.sha256")
}

func (suite *EncryptStreamTestSuite) TestStream() {
	md5 := md5.New()

	file, err := os.Open(suite.fileToEncrypt.Name())
	if err != nil {
		suite.FailNow("failed to open file", err)
	}

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
	_ = fs.Reader.Close()
}
func (suite *EncryptStreamTestSuite) TestStreamLargeFile() {
	md5 := md5.New()

	file, err := os.Open(suite.largeFileToEncrypt.Name())
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

	f, err := os.Create(fmt.Sprintf("%s/largefile2.c4gh", suite.tempDir))
	assert.NoError(suite.T(), err, "failed to create temp file")
	n, err := f.Write(enc)
	assert.NoError(suite.T(), err, "failed write data to temp file")
	assert.Equal(suite.T(), 2098172, n)
	_ = f.Close()

	os.Setenv("C4GH_PASSWORD", "") //nolint:errcheck
	assert.NoError(suite.T(), decrypt.Decrypt([]string{"decrypt", "-key", suite.privateKey.Name(), "--force-overwrite", f.Name()}), "decrypting encrypted file failed unexpectedly")
}
func (suite *EncryptStreamTestSuite) TestStream_noPublicKey() {
	var file *os.File
	_, err := Stream(file, [][32]byte{})
	assert.ErrorContains(suite.T(), err, "no public key supplied")
}
