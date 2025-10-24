package createkey

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/neicnordic/crypt4gh/keys"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type CreateKeyTests struct {
	suite.Suite
	tempDir string
}

func TestCreateKeyTestSuite(t *testing.T) {
	suite.Run(t, new(CreateKeyTests))
}

func (s *CreateKeyTests) SetupTest() {
	var err error

	// Create a temporary directory for our files
	s.tempDir, err = os.MkdirTemp(os.TempDir(), "sda-cli-test-")
	assert.NoError(s.T(), err)
}

func (s *CreateKeyTests) TearDownTest() {
	os.Remove(s.tempDir) //nolint:errcheck
}

func (s *CreateKeyTests) TestgenerateKeyPair() {
	testFileName := filepath.Join(s.tempDir, "keyfile")

	// none of the target files exist, no password used
	err := GenerateKeyPair(testFileName, "")
	assert.NoError(s.T(), err)

	// now the targets exist - should crash on public-key existing
	err = GenerateKeyPair(testFileName, "")
	assert.EqualError(s.T(), err, fmt.Sprintf("key pair with name '%v' seems to already exist, refusing to overwrite", testFileName))

	// remove the public key to test the private key exists error
	os.Remove(fmt.Sprintf("%s.pub.pem", testFileName)) //nolint:errcheck
	err = GenerateKeyPair(testFileName, "")
	assert.EqualError(s.T(), err, fmt.Sprintf("key pair with name '%v' seems to already exist, refusing to overwrite", testFileName))

	// remove the private key so we can try again
	os.Remove(fmt.Sprintf("%s.sec.pem", testFileName)) //nolint:errcheck

	password := "testPassword"

	// create new keys, this time with a password
	err = GenerateKeyPair(testFileName, password)
	assert.NoError(s.T(), err)

	// load the key again, to see that the password works
	keyFile, err := os.Open(filepath.Clean(fmt.Sprintf("%s.sec.pem", testFileName)))
	assert.NoError(s.T(), err)

	_, err = keys.ReadPrivateKey(keyFile, []byte(password))
	assert.NoError(s.T(), err)
}

func (s *CreateKeyTests) TestgenerateKeyPairPermission() {
	testFileName := filepath.Join(s.tempDir, "keyfile")

	// none of the target files exist, no password used
	err := GenerateKeyPair(testFileName, "")
	assert.NoError(s.T(), err)

	// test that the public key has correct permission
	pubFile, err := os.Lstat(testFileName + ".pub.pem")
	assert.NoError(s.T(), err)
	pubPerm := pubFile.Mode().Perm()
	if runtime.GOOS == "windows" {
		assert.Equal(s.T(), fs.FileMode(0666), pubPerm)
	} else {
		assert.Equal(s.T(), fs.FileMode(0644), pubPerm)
	}

	// test that the secret key has correct permission
	secFile, err := os.Lstat(testFileName + ".sec.pem")
	assert.NoError(s.T(), err)
	secPerm := secFile.Mode().Perm()
	if runtime.GOOS == "windows" {
		assert.Equal(s.T(), fs.FileMode(0666), pubPerm)
	} else {
		assert.Equal(s.T(), fs.FileMode(0600), secPerm)
	}
}
