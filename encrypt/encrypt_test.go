package encrypt

import (
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
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

func (s *EncryptTestSuite) SetupTest() {
	encryptCmd.Root().Flag("config").Value.Set("")
	encryptCmd.Flag("outdir").Value.Set("")
	encryptCmd.Flag("continue").Value.Set("false")
	encryptCmd.Flag("target").Value.Set("")
	publicKeyFileList = []string{}
	os.Args = []string{"", "encrypt"}

	// Create a temporary directory for our files
	s.tempDir = s.T().TempDir()

	var err error
	// Generate a crypt4gh key pair
	s.pubKeyData, s.secKeyData, err = keys.GenerateKeyPair()
	if err != nil {
		s.FailNow("failed to generate key pair", err)
	}

	// Write the keys to temporary files
	s.publicKey, err = os.CreateTemp(s.tempDir, "pubkey-")
	if err != nil {
		s.FailNow("failed to create temp public key test file", err)
	}

	if err = keys.WriteCrypt4GHX25519PublicKey(s.publicKey, s.pubKeyData); err != nil {
		s.FailNow("failed to write to public key test file", err)
	}
	_ = s.publicKey.Close()

	s.privateKey, err = os.CreateTemp(s.tempDir, "seckey-")
	if err != nil {
		s.FailNow("failed to create temp private key test file", err)
	}

	if err := keys.WriteCrypt4GHX25519PrivateKey(s.privateKey, s.secKeyData, []byte("")); err != nil {
		s.FailNow("failed to write to private key", err)
	}
	_ = s.privateKey.Close()

	s.multiPublicKey, err = os.CreateTemp(s.tempDir, "multi-pubkey-")
	if err != nil {
		s.FailNow("failed to create multi pub key test file", err)
	}

	input, err := os.ReadFile(s.publicKey.Name()) // #nosec G703
	if err != nil {
		s.FailNow("failed to read public key file", err)
	}

	if _, err := s.multiPublicKey.Write(append(input, input...)); err != nil {
		s.FailNow("failed to write to multi public key test file", err)
	}
	_ = s.multiPublicKey.Close()

	// create an existing test file with some known content
	s.fileToEncrypt, err = os.CreateTemp(s.tempDir, "testfile-")
	if err != nil {
		s.FailNow("failed to create test file", err)
	}

	if err := os.WriteFile(s.fileToEncrypt.Name(), []byte("content"), 0600); err != nil { // #nosec G703
		s.FailNow("failed to write to test file", err)
	}
	_ = s.fileToEncrypt.Close()

	// create an large test file with some known content
	s.largeFileToEncrypt, err = os.CreateTemp(s.tempDir, "largefile-")
	if err != nil {
		s.FailNow("failed to create largefile test file", err)
	}

	for range 2 * 1024 * 1024 {
		if _, err = s.largeFileToEncrypt.WriteString("a"); err != nil {
			s.FailNow("failed to write largefile test file", err)
		}
	}
	_ = s.largeFileToEncrypt.Close()
}

func (s *EncryptTestSuite) TearDownTest() {
	_ = os.Remove("checksum_encrypted.md5")
	_ = os.Remove("checksum_encrypted.sha256")
	_ = os.Remove("checksum_unencrypted.md5")
	_ = os.Remove("checksum_unencrypted.sha256")
}

func (s *EncryptTestSuite) TestEncryptNoConfigOrKey() {
	os.Args = []string{"", "encrypt", s.fileToEncrypt.Name()}
	assert.Equal(s.T(), errors.New("configuration file (.sda-cli-session) not found"), encryptCmd.Execute())
}
func (s *EncryptTestSuite) TestEncryptKeyNotExist() {
	notExistFile := filepath.Join(s.tempDir, "file-not-exists")
	_, notFoundError := os.Open(notExistFile)
	encryptCmd.Flag("key").Value.Set(notExistFile)
	os.Args = []string{"", "encrypt", s.fileToEncrypt.Name()}
	assert.Equal(s.T(), notFoundError, encryptCmd.Execute())
}

func (s *EncryptTestSuite) TestEncryptWithPubKeyFromTarget() {
	keyData, err := os.ReadFile(s.publicKey.Name()) // #nosec G703
	if err != nil {
		s.FailNow("failed to read public key from disk", err)
	}

	infoData := login.AuthInfo{
		PublicKey: base64.StdEncoding.EncodeToString(keyData),
	}
	responseData, err := json.Marshal(infoData)
	if err != nil {
		s.FailNow("failed to marshal JSON response", err)
	}

	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(responseData)
	}))
	defer mockServer.Close()

	os.Args = []string{"", "encrypt", s.fileToEncrypt.Name()}
	encryptCmd.Flag("target").Value.Set(mockServer.URL)
	assert.NoError(s.T(), encryptCmd.Execute(), "Encrypt from info failed unexpectedly")

	// check that encrypted file exist
	_, err = os.Stat(fmt.Sprintf("%s.c4gh", s.fileToEncrypt.Name())) // #nosec G703
	assert.NoError(s.T(), err)
}
func (s *EncryptTestSuite) TestEncryptWithExistingFile() {
	// create an existing encrypted test file
	encryptedFile := fmt.Sprintf("%s.c4gh", s.fileToEncrypt.Name())
	if err := os.WriteFile(encryptedFile, []byte("crypt4gh"), 0600); err != nil { // #nosec G703
		s.FailNow("failed to create encrypted test file to be overwritten", err)
	}

	os.Args = []string{"", "encrypt", s.fileToEncrypt.Name()}
	encryptCmd.Flag("key").Value.Set(s.publicKey.Name())
	assert.Equal(s.T(), errors.New("aborting"), encryptCmd.Execute())

	encryptedContent, err := os.ReadFile(encryptedFile) // #nosec G703
	if err != nil {
		s.FailNow("failed to read encrypted test file", err)
	}

	assert.Equal(s.T(), encryptedContent, []byte("crypt4gh"))
}

func (s *EncryptTestSuite) TestEncrypt() {
	os.Args = []string{"", "encrypt", s.fileToEncrypt.Name()}
	encryptCmd.Flag("key").Value.Set(s.publicKey.Name())
	encryptCmd.Flag("continue").Value.Set("true")
	assert.NoError(s.T(), encryptCmd.Execute())

	encryptedContent, err := os.Open(fmt.Sprintf("%s.c4gh", s.fileToEncrypt.Name())) // #nosec G703
	if err != nil {
		s.FailNow("failed to read encrypted test file", err)
	}
	defer encryptedContent.Close() //nolint:errcheck

	// Create crypt4gh reader
	crypt4GHReader, err := streaming.NewCrypt4GHReader(encryptedContent, s.secKeyData, nil)
	if err != nil {
		s.FailNow("failed to read decrypted encrypted test file", err)
	}
	defer crypt4GHReader.Close() //nolint:errcheck

	decryptedContent, err := io.ReadAll(crypt4GHReader)
	if err != nil {
		s.FailNow("failed to read decrypted encrypted file content", err)
	}

	assert.Equal(s.T(), []byte("content"), decryptedContent)
}

func (s *EncryptTestSuite) TestEncryptWithOutdir() {
	targetDir := filepath.Join(s.tempDir, "different_dir")

	if err := os.Mkdir(targetDir, 0700); err != nil {
		s.FailNow("failed to create temporary dir", err)
	}

	os.Args = []string{"", "encrypt", s.fileToEncrypt.Name()}
	encryptCmd.Flag("key").Value.Set(s.publicKey.Name())
	encryptCmd.Flag("outdir").Value.Set(targetDir)
	assert.NoError(s.T(), encryptCmd.Execute())

	// check that encrypted file does not exist in same dir as unencrypted file
	_, err := os.Stat(fmt.Sprintf("%s.c4gh", s.fileToEncrypt.Name())) // #nosec G703
	msg := "no such file or directory"
	if runtime.GOOS == "windows" {
		msg = "The system cannot find the file specified."
	}
	assert.ErrorContains(s.T(), err, msg)

	encryptedContent, err := os.Open(fmt.Sprintf("%s.c4gh", filepath.Join(targetDir, filepath.Base(s.fileToEncrypt.Name())))) // #nosec G703
	if err != nil {
		s.FailNow("failed to read encrypted test file", err)
	}
	defer encryptedContent.Close() //nolint:errcheck

	// Create crypt4gh reader
	crypt4GHReader, err := streaming.NewCrypt4GHReader(encryptedContent, s.secKeyData, nil)
	if err != nil {
		s.FailNow("failed to read decrypted encrypted test file", err)
	}
	defer crypt4GHReader.Close() //nolint:errcheck

	decryptedContent, err := io.ReadAll(crypt4GHReader)
	if err != nil {
		s.FailNow("failed to read decrypted encrypted file content", err)
	}

	assert.Equal(s.T(), []byte("content"), decryptedContent)
}
func (s *EncryptTestSuite) TestStream() {
	md5hash := md5.New()

	file, err := os.Open(s.fileToEncrypt.Name()) // #nosec G703
	if err != nil {
		s.FailNow("failed to open file", err)
	}

	fs, err := Stream(file, [][32]byte{s.pubKeyData})
	assert.NoError(s.T(), err, "failed to create encryption stream")
	// make sure that no data is being read in order to save on memory
	assert.Equal(s.T(), hex.EncodeToString(md5hash.Sum(nil)), hex.EncodeToString(fs.UnencryptedMD5.Sum(nil)))

	enc, err := io.ReadAll(fs.Reader)
	assert.NoError(s.T(), err, "failed to read from encryption stream")
	assert.Equal(s.T(), "crypt4gh", string(enc[:8]))
	md5hash.Write([]byte("content"))
	// ensure that the MD5 is what we expect it to be after the file has been read fully.
	assert.Equal(s.T(), hex.EncodeToString(md5hash.Sum(nil)), hex.EncodeToString(fs.UnencryptedMD5.Sum(nil)))

	_ = file.Close()
	_ = fs.Reader.Close()
}
func (s *EncryptTestSuite) TestStreamLargeFile() {
	md5hash := md5.New()

	file, err := os.Open(s.largeFileToEncrypt.Name()) // #nosec G703
	assert.NoError(s.T(), err, "opening file failed unexpectedly")
	info, _ := file.Stat()
	assert.Equal(s.T(), int64(2*1024*1024), info.Size())

	fs, err := Stream(file, [][32]byte{s.pubKeyData})
	assert.NoError(s.T(), err, "failed to create encryption stream")
	// make sure that no data is being read in order to save on memory
	assert.Equal(s.T(), hex.EncodeToString(md5hash.Sum(nil)), hex.EncodeToString(fs.UnencryptedMD5.Sum(nil)))

	enc, err := io.ReadAll(fs.Reader)
	assert.NoError(s.T(), err, "failed to read from encryption stream")
	_ = fs.Reader.Close()
	_ = file.Close()

	assert.Equal(s.T(), "crypt4gh", string(enc[:8]))
	assert.Greater(s.T(), len(enc), 2*1024*1024)
	assert.Equal(s.T(), 2098172, len(enc))
	// ensure that the MD5 is what we expect it to be after the file has been read fully.
	assert.Equal(s.T(), "de89461b64701958984c95d1bfb0065a", hex.EncodeToString(fs.UnencryptedMD5.Sum(nil)))

	f, err := os.Create(filepath.Join(s.tempDir, "largefile2.c4gh"))
	assert.NoError(s.T(), err, "failed to create temp file")
	n, err := f.Write(enc)
	assert.NoError(s.T(), err, "failed write data to temp file")
	assert.Equal(s.T(), 2098172, n)
	_ = f.Close()

	_ = os.Setenv("C4GH_PASSWORD", "")
	decrypt.SetFlags("key", s.privateKey.Name())
	decrypt.SetFlags("force-overwrite", "true")
	assert.NoError(s.T(), decrypt.Decrypt([]string{f.Name()}), "decrypting encrypted file failed unexpectedly")
}
func (s *EncryptTestSuite) TestStream_noPublicKey() {
	var file *os.File
	_, err := Stream(file, [][32]byte{})
	assert.ErrorContains(s.T(), err, "no public key supplied")
}

func (s *EncryptTestSuite) TestCalculateHashes() {
	_, notFoundError := os.Open(filepath.Join(s.tempDir, "does-not-exist"))

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
			unencryptedFile:           s.fileToEncrypt.Name(),
			encryptedFile:             filepath.Join(s.tempDir, "does-not-exist"),
			expectedError:             notFoundError,
			expectedUnencryptedMd5:    "",
			expectedUnencryptedSha256: "",
			expectedEncryptedMd5:      "",
			expectedEncryptedSha256:   "",
		}, {
			testName:                  "UnencryptedNotExist",
			unencryptedFile:           filepath.Join(s.tempDir, "does-not-exist"),
			encryptedFile:             s.fileToEncrypt.Name(),
			expectedError:             notFoundError,
			expectedUnencryptedMd5:    "",
			expectedUnencryptedSha256: "",
			expectedEncryptedMd5:      "",
			expectedEncryptedSha256:   "",
		}, {
			testName:                  "BothExist",
			unencryptedFile:           s.fileToEncrypt.Name(),
			encryptedFile:             s.fileToEncrypt.Name(),
			expectedError:             nil,
			expectedUnencryptedMd5:    "9a0364b9e99bb480dd25e1f0284c8555",
			expectedUnencryptedSha256: "ed7002b439e9ac845f22357d822bac1444730fbdb6016d3ec9432297b9ec9f73",
			expectedEncryptedMd5:      "9a0364b9e99bb480dd25e1f0284c8555",
			expectedEncryptedSha256:   "ed7002b439e9ac845f22357d822bac1444730fbdb6016d3ec9432297b9ec9f73",
		},
	} {
		s.T().Run(test.testName, func(t *testing.T) {
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

func (s *EncryptTestSuite) TestCheckFiles() {
	// create an existing encrypted test file
	encryptedFile, err := os.CreateTemp(s.tempDir, "encrypted-input")
	if err != nil {
		s.FailNow("failed to create encrypted input test file", err)
	}
	if _, err := encryptedFile.Write([]byte("crypt4gh")); err != nil {
		s.FailNow("failed to write to encrypted input test file", err)
	}
	_ = encryptedFile.Close()

	for _, test := range []struct {
		testName                       string
		unencryptedFile, encryptedFile string
		expectedError                  error
	}{
		{
			testName:        "EncryptedNotExist",
			unencryptedFile: s.fileToEncrypt.Name(),
			encryptedFile:   "does-not-exist",
			expectedError:   nil,
		}, {
			testName:        "BothExist",
			unencryptedFile: s.fileToEncrypt.Name(),
			encryptedFile:   s.fileToEncrypt.Name(),
			expectedError:   fmt.Errorf("outfile %s already exists", s.fileToEncrypt.Name()),
		}, {
			testName:        "UnencryptedNotExist",
			unencryptedFile: "does-not-exist",
			encryptedFile:   s.fileToEncrypt.Name(),
			expectedError:   errors.New("cannot read input file does-not-exist"),
		}, {
			testName:        "EncryptedAsInput",
			unencryptedFile: encryptedFile.Name(),
			encryptedFile:   "does-not-exist",
			expectedError:   fmt.Errorf("input file %s is already encrypted(.c4gh)", encryptedFile.Name()),
		},
	} {
		s.T().Run(test.testName, func(t *testing.T) {
			fileSet := helpers.EncryptionFileSet{Unencrypted: test.unencryptedFile, Encrypted: test.encryptedFile}
			assert.Equal(t, test.expectedError, checkFiles([]helpers.EncryptionFileSet{fileSet}))
		})
	}
}

func (s *EncryptTestSuite) TestCheckKeyFile() {
	specs := newKeySpecs()

	notAKeyFile := filepath.Join(s.tempDir, "not_a_key")
	if err := os.WriteFile(notAKeyFile, []byte("not a key file"), 0600); err != nil {
		s.FailNow("failed to write to not a key file", err)
	}

	notExistFilePath := filepath.Join(s.tempDir, "does-not-exist")
	_, notFoundError := os.Open(notExistFilePath)

	for _, test := range []struct {
		testName        string
		pubKeyFileName  string
		expectedKeySize int64
		expectedError   error
	}{
		{
			testName:        "MultiPubKey",
			pubKeyFileName:  s.multiPublicKey.Name(),
			expectedKeySize: int64(230),
			expectedError:   nil,
		}, {
			testName:        "PubKey",
			pubKeyFileName:  s.publicKey.Name(),
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
		s.T().Run(test.testName, func(t *testing.T) {
			keySize, err := checkKeyFile(test.pubKeyFileName, specs)
			assert.Equal(t, test.expectedError, err)
			assert.Equal(t, test.expectedKeySize, keySize)
		})
	}
}

func (s *EncryptTestSuite) TestReadMultiPublicKeyFile() {
	specs := newKeySpecs()

	notExistFilePath := filepath.Join(s.tempDir, "does-not-exist")
	_, notFoundError := os.Open(notExistFilePath)

	for _, test := range []struct {
		testName            string
		multiPubKeyFileName string
		expectedFileContent *[32]byte
		expectedError       error
	}{
		{
			testName:            "FileExists",
			multiPubKeyFileName: s.multiPublicKey.Name(),
			expectedError:       nil,
			expectedFileContent: &s.pubKeyData,
		}, {
			testName:            "FileDoesNotExist",
			multiPubKeyFileName: notExistFilePath,
			expectedFileContent: nil,
			expectedError:       notFoundError,
		},
	} {
		s.T().Run(test.testName, func(t *testing.T) {
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

func (s *EncryptTestSuite) TestReadPublicKeyFile() {
	notExistFilePath := filepath.Join(s.tempDir, "does-not-exist")
	_, notFoundError := os.Open(notExistFilePath)

	for _, test := range []struct {
		testName            string
		pubKeyFileName      string
		expectedFileContent *[32]byte
		expectedError       error
	}{
		{
			testName:            "FileExists",
			pubKeyFileName:      s.publicKey.Name(),
			expectedError:       nil,
			expectedFileContent: &s.pubKeyData,
		}, {
			testName:            "FileDoesNotExist",
			pubKeyFileName:      notExistFilePath,
			expectedFileContent: nil,
			expectedError:       notFoundError,
		},
	} {
		s.T().Run(test.testName, func(t *testing.T) {
			publicKey, err := readPublicKeyFile(test.pubKeyFileName)
			assert.Equal(t, test.expectedError, err)
			assert.Equal(t, test.expectedFileContent, publicKey)
		})
	}
}
