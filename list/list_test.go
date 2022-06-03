package list

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type TestSuite struct {
	suite.Suite
}

func TestConfigTestSuite(t *testing.T) {
	suite.Run(t, new(TestSuite))
}

func (suite *TestSuite) SetupTest() {

}

func (suite *TestSuite) TestNoConfig() {

	os.Args = []string{"list"}

	err := List(os.Args)
	assert.EqualError(suite.T(), err, "failed to find an s3 configuration file for listing data")
}

func (suite *TestSuite) TestTooManyArgs() {

	os.Args = []string{"list", "arg1", "arg2"}

	err := List(os.Args)
	assert.EqualError(suite.T(), err, "failed to parse prefix, only one is allowed")
}
