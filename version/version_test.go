package version

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type VersionTests struct {
	suite.Suite
}

func TestVersionTestSuite(t *testing.T) {
	suite.Run(t, new(VersionTests))
}

func (suite *VersionTests) TestGetVersion() {

	// get version
	err := Version("development")
	assert.NoError(suite.T(), err)

}
