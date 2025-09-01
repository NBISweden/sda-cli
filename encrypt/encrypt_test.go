package encrypt

import (
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
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

	"github.com/NBISweden/sda-cli/decrypt"
	"github.com/NBISweden/sda-cli/helpers"
	"github.com/NBISweden/sda-cli/login"
	"github.com/neicnordic/crypt4gh/keys"
	"github.com/neicnordic/crypt4gh/streaming"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type EncryptTestSuite struct {
	suite.Suite
	tempDir            string
	pubKeyData         [32]byte
	secKeyData         [32]byte
	publicKey          *os.File
	privateKey         *os.File
	multiPublicKey     *os.File
	fileToEncrypt      *os.File
	largeFileToEncrypt *os.File
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
	suite.pubKeyData, suite.secKeyData, err = keys.GenerateKeyPair()
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

	err = keys.WriteCrypt4GHX25519PrivateKey(suite.privateKey, suite.secKeyData, []byte(""))
	if err != nil {
		suite.FailNow("failed to write to private key", err)
	}
	_ = suite.privateKey.Close()

	suite.multiPublicKey, err = os.CreateTemp(suite.tempDir, "multi-pubkey-")
	if err != nil {
		suite.FailNow("failed to create multi pub key test file", err)
	}

	input, err := os.ReadFile(suite.publicKey.Name())
	if err != nil {
		suite.FailNow("failed to read public key file", err)
	}

	if _, err := suite.multiPublicKey.Write(append(input, input...)); err != nil {
		suite.FailNow("failed to write to multi public key test file", err)
	}
	_ = suite.multiPublicKey.Close()

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
	notExistFile := filepath.Join(suite.tempDir, "file-not-exists")
	_, notFoundError := os.Open(notExistFile)
	assert.Equal(suite.T(), notFoundError, Encrypt([]string{
		"encrypt",
		"-key",
		notExistFile,
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
	targetDir := filepath.Join(suite.tempDir, "different_dir")

	if err := os.Mkdir(targetDir, 0700); err != nil {
		suite.FailNow("failed to create temporary dir", err)
	}

	err := Encrypt([]string{
		"encrypt",
		"-key",
		suite.publicKey.Name(),
		"-outdir",
		targetDir,
		suite.fileToEncrypt.Name(),
	})
	assert.NoError(suite.T(), err)

	// check that encrypted file does not exist in same dir as unencrypted file
	_, err = os.Stat(fmt.Sprintf("%s.c4gh", suite.fileToEncrypt.Name()))
	msg := "no such file or directory"
	if runtime.GOOS == "windows" {
		msg = "The system cannot find the file specified."
	}
	assert.ErrorContains(suite.T(), err, msg)

	encryptedContent, err := os.Open(fmt.Sprintf("%s.c4gh", filepath.Join(targetDir, filepath.Base(suite.fileToEncrypt.Name()))))
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
func (suite *EncryptTestSuite) TestStream() {
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
func (suite *EncryptTestSuite) TestStreamLargeFile() {
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

	f, err := os.Create(filepath.Join(suite.tempDir, "largefile2.c4gh"))
	assert.NoError(suite.T(), err, "failed to create temp file")
	n, err := f.Write(enc)
	assert.NoError(suite.T(), err, "failed write data to temp file")
	assert.Equal(suite.T(), 2098172, n)
	_ = f.Close()

	_ = os.Setenv("C4GH_PASSWORD", "")
	assert.NoError(suite.T(), decrypt.Decrypt([]string{"decrypt", "-key", suite.privateKey.Name(), "--force-overwrite", f.Name()}), "decrypting encrypted file failed unexpectedly")
}
func (suite *EncryptTestSuite) TestStream_noPublicKey() {
	var file *os.File
	_, err := Stream(file, [][32]byte{})
	assert.ErrorContains(suite.T(), err, "no public key supplied")
}

func (suite *EncryptTestSuite) TestCalculateHashes() {

	_, notFoundError := os.Open(filepath.Join(suite.tempDir, "does-not-exist"))

	for _, test := range []struct {
		testName                       string
		unencryptedFile, encryptedFile string
		expectedError                  error
		expectedUnencryptedMd5         string
		expectedUnencryptedSha256      string
		expectedEncryptedMd5           string
		expectedEncryptedSha256        string
	}{
		{
			testName:                  "EncryptedNotExist",
			unencryptedFile:           suite.fileToEncrypt.Name(),
			encryptedFile:             filepath.Join(suite.tempDir, "does-not-exist"),
			expectedError:             notFoundError,
			expectedUnencryptedMd5:    "",
			expectedUnencryptedSha256: "",
			expectedEncryptedMd5:      "",
			expectedEncryptedSha256:   "",
		}, {
			testName:                  "UnencryptedNotExist",
			unencryptedFile:           filepath.Join(suite.tempDir, "does-not-exist"),
			encryptedFile:             suite.fileToEncrypt.Name(),
			expectedError:             notFoundError,
			expectedUnencryptedMd5:    "",
			expectedUnencryptedSha256: "",
			expectedEncryptedMd5:      "",
			expectedEncryptedSha256:   "",
		}, {
			testName:                  "BothExist",
			unencryptedFile:           suite.fileToEncrypt.Name(),
			encryptedFile:             suite.fileToEncrypt.Name(),
			expectedError:             nil,
			expectedUnencryptedMd5:    "9a0364b9e99bb480dd25e1f0284c8555",
			expectedUnencryptedSha256: "ed7002b439e9ac845f22357d822bac1444730fbdb6016d3ec9432297b9ec9f73",
			expectedEncryptedMd5:      "9a0364b9e99bb480dd25e1f0284c8555",
			expectedEncryptedSha256:   "ed7002b439e9ac845f22357d822bac1444730fbdb6016d3ec9432297b9ec9f73",
		},
	} {
		suite.T().Run(test.testName, func(t *testing.T) {
			fileSet := helpers.EncryptionFileSet{Unencrypted: test.unencryptedFile, Encrypted: test.encryptedFile}
			hashes, err := calculateHashes(fileSet)

			assert.Equal(t, test.expectedError, err)

			if hashes != nil {
				assert.Equal(t, test.expectedUnencryptedMd5, hashes.unencryptedMd5)
				assert.Equal(t, test.expectedUnencryptedSha256, hashes.unencryptedSha256)
				assert.Equal(t, test.expectedEncryptedMd5, hashes.encryptedMd5)
				assert.Equal(t, test.expectedEncryptedSha256, hashes.encryptedSha256)

				return
			}

			assert.Equal(t, test.expectedUnencryptedMd5, "")
			assert.Equal(t, test.expectedUnencryptedSha256, "")
			assert.Equal(t, test.expectedEncryptedMd5, "")
			assert.Equal(t, test.expectedEncryptedSha256, "")
		})
	}
}

func (suite *EncryptTestSuite) TestCheckFiles() {
	// create an existing encrypted test file
	encryptedFile, err := os.CreateTemp(suite.tempDir, "encrypted-input")
	if err != nil {
		suite.FailNow("failed to create encrypted input test file", err)
	}

	if _, err := encryptedFile.Write([]byte("crypt4gh")); err != nil {
		suite.FailNow("failed to write to encrypted input test file", err)
	}
	_ = encryptedFile.Close()

	for _, test := range []struct {
		testName                       string
		unencryptedFile, encryptedFile string
		expectedError                  error
	}{
		{
			testName:        "EncryptedNotExist",
			unencryptedFile: suite.fileToEncrypt.Name(),
			encryptedFile:   "does-not-exist",
			expectedError:   nil,
		}, {
			testName:        "BothExist",
			unencryptedFile: suite.fileToEncrypt.Name(),
			encryptedFile:   suite.fileToEncrypt.Name(),
			expectedError:   fmt.Errorf("outfile %s already exists", suite.fileToEncrypt.Name()),
		}, {
			testName:        "UnencryptedNotExist",
			unencryptedFile: "does-not-exist",
			encryptedFile:   suite.fileToEncrypt.Name(),
			expectedError:   fmt.Errorf("cannot read input file does-not-exist"),
		}, {
			testName:        "EncryptedAsInput",
			unencryptedFile: encryptedFile.Name(),
			encryptedFile:   "does-not-exist",
			expectedError:   fmt.Errorf("input file %s is already encrypted(.c4gh)", encryptedFile.Name()),
		},
	} {
		suite.T().Run(test.testName, func(t *testing.T) {
			fileSet := helpers.EncryptionFileSet{Unencrypted: test.unencryptedFile, Encrypted: test.encryptedFile}
			assert.Equal(t, test.expectedError, checkFiles([]helpers.EncryptionFileSet{fileSet}))
		})
	}
}

func (suite *EncryptTestSuite) TestCheckKeyFile() {
	specs := newKeySpecs()

	notAKeyFile := filepath.Join(suite.tempDir, "not_a_key")
	if err := os.WriteFile(notAKeyFile, []byte("not a key file"), 0600); err != nil {
		suite.FailNow("failed to write to not a key file", err)
	}

	notExistFilePath := filepath.Join(suite.tempDir, "does-not-exist")
	_, notFoundError := os.Open(notExistFilePath)

	for _, test := range []struct {
		testName        string
		pubKeyFileName  string
		expectedKeySize int64
		expectedError   error
	}{
		{
			testName:        "MultiPubKey",
			pubKeyFileName:  suite.multiPublicKey.Name(),
			expectedKeySize: int64(230),
			expectedError:   nil,
		}, {
			testName:        "PubKey",
			pubKeyFileName:  suite.publicKey.Name(),
			expectedKeySize: int64(115),
			expectedError:   nil,
		}, {
			testName:        "FileDoesNotExist",
			pubKeyFileName:  notExistFilePath,
			expectedKeySize: int64(0),
			expectedError:   notFoundError,
		}, {
			testName:        "NotAKeyFile",
			pubKeyFileName:  notAKeyFile,
			expectedKeySize: int64(0),
			expectedError:   fmt.Errorf("invalid key format in file: %v", notAKeyFile),
		},
	} {
		suite.T().Run(test.testName, func(t *testing.T) {
			keySize, err := checkKeyFile(test.pubKeyFileName, specs)
			assert.Equal(t, test.expectedError, err)
			assert.Equal(t, test.expectedKeySize, keySize)

		})
	}
}

func (suite *EncryptTestSuite) TestReadMultiPublicKeyFile() {
	specs := newKeySpecs()

	notExistFilePath := filepath.Join(suite.tempDir, "does-not-exist")
	_, notFoundError := os.Open(notExistFilePath)

	for _, test := range []struct {
		testName            string
		multiPubKeyFileName string
		expectedFileContent *[32]byte
		expectedError       error
	}{
		{
			testName:            "FileExists",
			multiPubKeyFileName: suite.multiPublicKey.Name(),
			expectedError:       nil,
			expectedFileContent: &suite.pubKeyData,
		}, {
			testName:            "FileDoesNotExist",
			multiPubKeyFileName: notExistFilePath,
			expectedFileContent: nil,
			expectedError:       notFoundError,
		},
	} {
		suite.T().Run(test.testName, func(t *testing.T) {
			publicKeys, err := readMultiPublicKeyFile(test.multiPubKeyFileName, specs)
			assert.Equal(t, test.expectedError, err)

			if publicKeys == nil && test.expectedFileContent != nil {
				t.Error(t, "public keys was expected but returned nil")
				t.FailNow()
			}

			if publicKeys == nil {
				return
			}
			for _, key := range *publicKeys {
				assert.Equal(t, *test.expectedFileContent, key)
			}
		})
	}
}

func (suite *EncryptTestSuite) TestReadPublicKeyFile() {
	notExistFilePath := filepath.Join(suite.tempDir, "does-not-exist")
	_, notFoundError := os.Open(notExistFilePath)

	for _, test := range []struct {
		testName            string
		pubKeyFileName      string
		expectedFileContent *[32]byte
		expectedError       error
	}{
		{
			testName:            "FileExists",
			pubKeyFileName:      suite.publicKey.Name(),
			expectedError:       nil,
			expectedFileContent: &suite.pubKeyData,
		}, {
			testName:            "FileDoesNotExist",
			pubKeyFileName:      notExistFilePath,
			expectedFileContent: nil,
			expectedError:       notFoundError,
		},
	} {
		suite.T().Run(test.testName, func(t *testing.T) {

			publicKey, err := readPublicKeyFile(test.pubKeyFileName)
			assert.Equal(t, test.expectedError, err)
			assert.Equal(t, test.expectedFileContent, publicKey)
		})
	}
}
