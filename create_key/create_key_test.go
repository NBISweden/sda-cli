package createkey

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
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

func (suite *CreateKeyTests) SetupTest() {

	var err error

	// Create a temporary directory for our files
	suite.tempDir, err = os.MkdirTemp(os.TempDir(), "sda-cli-test-")
	assert.NoError(suite.T(), err)
}

func (suite *CreateKeyTests) TearDownTest() {
	os.Remove(suite.tempDir)
}

func (suite *CreateKeyTests) TestgenerateKeyPair() {

	testFileName := filepath.Join(suite.tempDir, "keyfile")

	// none of the target files exist, no password used
	err := GenerateKeyPair(testFileName, "")
	assert.NoError(suite.T(), err)

	// now the targets exist - should crash on public-key existing
	err = GenerateKeyPair(testFileName, "")
	assert.EqualError(suite.T(), err, fmt.Sprintf("key pair with name '%v' seems to already exist, refusing to overwrite", testFileName))

	// remove the public key to test the private key exists error
	os.Remove(fmt.Sprintf("%s.pub.pem", testFileName))
	err = GenerateKeyPair(testFileName, "")
	assert.EqualError(suite.T(), err, fmt.Sprintf("key pair with name '%v' seems to already exist, refusing to overwrite", testFileName))

	// remove the private key so we can try again
	os.Remove(fmt.Sprintf("%s.sec.pem", testFileName))

	password := "testPassword"

	// create new keys, this time with a password
	err = GenerateKeyPair(testFileName, password)
	assert.NoError(suite.T(), err)

	// load the key again, to see that the password works
	keyFile, err := os.Open(filepath.Clean(fmt.Sprintf("%s.sec.pem", testFileName)))
	assert.NoError(suite.T(), err)

	_, err = keys.ReadPrivateKey(keyFile, []byte(password))
	assert.NoError(suite.T(), err)
}

func (suite *CreateKeyTests) TestgenerateKeyPairPermission() {

	testFileName := filepath.Join(suite.tempDir, "keyfile")

	// none of the target files exist, no password used
	err := GenerateKeyPair(testFileName, "")
	assert.NoError(suite.T(), err)

	// test that the public key has correct permission
	pubFile, err := os.Lstat(testFileName + ".pub.pem")
	assert.NoError(suite.T(), err)
	pubPerm := pubFile.Mode().Perm()
	assert.Equal(suite.T(), pubPerm, fs.FileMode(0644))

	// test that the secret key has correct permission
	secFile, err := os.Lstat(testFileName + ".sec.pem")
	assert.NoError(suite.T(), err)
	secPerm := secFile.Mode().Perm()
	assert.Equal(suite.T(), secPerm, fs.FileMode(0600))

}
