package createKey

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

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
	suite.tempDir, err = ioutil.TempDir(os.TempDir(), "sda-cli-test-")
	assert.NoError(suite.T(), err)
}

func (suite *CreateKeyTests) TearDownTest() {
	os.Remove(suite.tempDir)
}

func (suite *CreateKeyTests) TestgenerateKeyPair() {

	testFileName := filepath.Join(suite.tempDir, "keyfile")

	// none of the target files exist
	err := generateKeyPair(testFileName, "")
	assert.NoError(suite.T(), err)

	// now the targets exist - should crash on public-key existing
	err = generateKeyPair(testFileName, "")
	assert.EqualError(suite.T(), err, fmt.Sprintf("Key pair with name '%v' seems to already exist, refusing to overwrite", testFileName))

	// remove the public key to test the private key exists error
	os.Remove(fmt.Sprintf("%s.pub.pem", testFileName))
	err = generateKeyPair(testFileName, "")
	assert.EqualError(suite.T(), err, fmt.Sprintf("Key pair with name '%v' seems to already exist, refusing to overwrite", testFileName))

	// remove the private key just in case it would mess with other tests
	os.Remove(fmt.Sprintf("%s.sec.pem", testFileName))
}
