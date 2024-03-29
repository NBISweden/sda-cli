package createkey

import (
	"fmt"
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
