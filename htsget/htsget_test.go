package htsget

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type TestSuite struct {
	suite.Suite
	tempDir     string
	fileContent []byte
	testFile    *os.File
}

func TestConfigTestSuite(t *testing.T) {
	suite.Run(t, new(TestSuite))
}

func (suite *TestSuite) TestNoArgument() {

	os.Args = []string{"htsget"}

	err := Htsget(os.Args)
	assert.EqualError(suite.T(), err, "missing required arguments, dataset, filename, htsgethost and key are required")
}
