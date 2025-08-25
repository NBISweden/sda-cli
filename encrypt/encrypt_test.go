package encrypt

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/NBISweden/sda-cli/login"
	"github.com/neicnordic/crypt4gh/keys"
	"github.com/neicnordic/crypt4gh/streaming"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type EncryptTestSuite struct {
	suite.Suite
	tempDir       string
	publicKey     *os.File
	fileToEncrypt *os.File
	secKeyData    [32]byte
}

func TestEncryptTestSuite(t *testing.T) {
	suite.Run(t, new(EncryptTestSuite))
}

func (suite *EncryptTestSuite) SetupTest() {
	// Reset flag values from any previous test invocation
	Args = flag.NewFlagSet("encrypt", flag.ContinueOnError)
	outDir = Args.String("outdir", "", "Output directory for encrypted files.")
	continueEncrypt = Args.Bool("continue", false, "Skip files with errors and continue processing others. Defaults to 'false'.")
	target = Args.String("target", "", "Client target associated with the public key.")
	Args.Func("key", "Public key file(s) to use for encryption. This flag can be specified\nmultiple times to encrypt files with multiple public keys. \nKey files may contain concatenated keys.", func(s string) error {
		publicKeyFileList = append(publicKeyFileList, s)

		return nil
	})
	publicKeyFileList = nil

	// Create a temporary directory for our files
	suite.tempDir = suite.T().TempDir()

	var err error

	// Generate a crypt4gh key pair
	var pubKeyData [32]byte
	pubKeyData, suite.secKeyData, err = keys.GenerateKeyPair()
	if err != nil {
		suite.FailNow("failed to generate key pair", err)
	}

	// Write the keys to temporary files
	suite.publicKey, err = os.CreateTemp(suite.tempDir, "pubkey-")
	if err != nil {
		suite.FailNow("failed to create temp public key test file", err)
	}

	if err = keys.WriteCrypt4GHX25519PublicKey(suite.publicKey, pubKeyData); err != nil {
		suite.FailNow("failed to write to public key test file", err)
	}
	_ = suite.publicKey.Close()

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

}

func (suite *EncryptTestSuite) TearDownTest() {
	_ = os.Remove("checksum_encrypted.md5")
	_ = os.Remove("checksum_encrypted.sha256")
	_ = os.Remove("checksum_unencrypted.md5")
	_ = os.Remove("checksum_unencrypted.sha256")
}

func (suite *EncryptTestSuite) TestEncryptNoConfigOrKey() {
	assert.Equal(suite.T(), errors.New("configuration file (.sda-cli-session) not found"), Encrypt([]string{
		"encrypt",
		suite.fileToEncrypt.Name(),
	}))

}
func (suite *EncryptTestSuite) TestEncryptKeyNotExist() {
	_, notFoundError := os.Open("file-not-exists")
	assert.Equal(suite.T(), notFoundError, Encrypt([]string{
		"encrypt",
		"-key",
		"file-not-exists",
		suite.fileToEncrypt.Name(),
	}))
}

func (suite *EncryptTestSuite) TestEncryptWithPubKeyFromTarget() {
	publicKeyFileList = nil
	keyData, err := os.ReadFile(suite.publicKey.Name())
	if err != nil {
		suite.FailNow("failed to read public key from disk", err)
	}

	infoData := login.AuthInfo{
		PublicKey: base64.StdEncoding.EncodeToString(keyData),
	}
	responseData, err := json.Marshal(infoData)
	if err != nil {
		suite.FailNow("failed to marshal JSON response", err)
	}

	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(responseData)
	}))
	defer mockServer.Close()

	assert.NoError(suite.T(), Encrypt([]string{
		"encrypt",
		"-target",
		mockServer.URL,
		suite.fileToEncrypt.Name(),
	}), "Encrypt from info failed unexpectedly")

	// check that encrypted file exist
	_, err = os.Stat(fmt.Sprintf("%s.c4gh", suite.fileToEncrypt.Name()))
	assert.NoError(suite.T(), err)

}
func (suite *EncryptTestSuite) TestEncryptWithExistingFile() {
	// create an existing encrypted test file
	encryptedFile := fmt.Sprintf("%s.c4gh", suite.fileToEncrypt.Name())
	if err := os.WriteFile(encryptedFile, []byte("crypt4gh"), 0600); err != nil {
		suite.FailNow("failed to create encrypted test file to be overwritten", err)
	}

	err := Encrypt([]string{
		"encrypt",
		"-key",
		suite.publicKey.Name(),
		suite.fileToEncrypt.Name(),
	})
	assert.Equal(suite.T(), errors.New("aborting"), err)

	encryptedContent, err := os.ReadFile(encryptedFile)
	if err != nil {
		suite.FailNow("failed to read encrypted test file", err)
	}

	assert.Equal(suite.T(), encryptedContent, []byte("crypt4gh"))
}
func (suite *EncryptTestSuite) TestEncryptWithExistingFileAndContinue() {
	// create an existing encrypted test file
	encryptedFile := fmt.Sprintf("%s.c4gh", suite.fileToEncrypt.Name())
	if err := os.WriteFile(encryptedFile, []byte("crypt4gh"), 0600); err != nil {
		suite.FailNow("failed to create encrypted test file to be overwritten", err)
	}

	assert.Equal(suite.T(), errors.Join(errors.New("no input files"), errors.New("(1/1) files skipped")),
		Encrypt([]string{
			"encrypt",
			"-key",
			suite.publicKey.Name(),
			"-continue",
			suite.fileToEncrypt.Name(),
		}),
	)

	encryptedContent, err := os.ReadFile(encryptedFile)
	if err != nil {
		suite.FailNow("failed to read encrypted test file", err)
	}

	assert.Equal(suite.T(), encryptedContent, []byte("crypt4gh"))
}

func (suite *EncryptTestSuite) TestEncrypt() {
	err := Encrypt([]string{
		"encrypt",
		"-key",
		suite.publicKey.Name(),
		"-continue",
		suite.fileToEncrypt.Name(),
	})
	assert.NoError(suite.T(), err)

	encryptedContent, err := os.Open(fmt.Sprintf("%s.c4gh", suite.fileToEncrypt.Name()))
	if err != nil {
		suite.FailNow("failed to read encrypted test file", err)
	}

	// Create crypt4gh reader
	crypt4GHReader, err := streaming.NewCrypt4GHReader(encryptedContent, suite.secKeyData, nil)
	if err != nil {
		suite.FailNow("failed to read decrypted encrypted test file", err)
	}

	decryptedContent, err := io.ReadAll(crypt4GHReader)
	if err != nil {
		suite.FailNow("failed to read decrypted encrypted file content", err)
	}

	assert.Equal(suite.T(), []byte("content"), decryptedContent)
}

func (suite *EncryptTestSuite) TestEncryptWithOutdir() {
	if err := os.Mkdir(fmt.Sprintf("%s/different_dir", suite.tempDir), 0700); err != nil {
		suite.FailNow("failed to create temporary dir", err)
	}

	err := Encrypt([]string{
		"encrypt",
		"-key",
		suite.publicKey.Name(),
		"-outdir",
		fmt.Sprintf("%s/different_dir", suite.tempDir),
		suite.fileToEncrypt.Name()})
	assert.NoError(suite.T(), err)

	// check that encrypted file does not exist in same dir as unencrypted file
	_, err = os.Stat(fmt.Sprintf("%s.c4gh", suite.fileToEncrypt.Name()))
	msg := "no such file or directory"
	if runtime.GOOS == "windows" {
		msg = "The system cannot find the file specified."
	}
	assert.ErrorContains(suite.T(), err, msg)

	encryptedContent, err := os.Open(fmt.Sprintf("%s/different_dir/%s.c4gh", suite.tempDir, filepath.Base(suite.fileToEncrypt.Name())))
	if err != nil {
		suite.FailNow("failed to read encrypted test file", err)
	}

	// Create crypt4gh reader
	crypt4GHReader, err := streaming.NewCrypt4GHReader(encryptedContent, suite.secKeyData, nil)
	if err != nil {
		suite.FailNow("failed to read decrypted encrypted test file", err)
	}

	decryptedContent, err := io.ReadAll(crypt4GHReader)
	if err != nil {
		suite.FailNow("failed to read decrypted encrypted file content", err)
	}

	assert.Equal(suite.T(), []byte("content"), decryptedContent)
}
