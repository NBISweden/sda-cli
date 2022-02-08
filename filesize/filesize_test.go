package filesize

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
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

func (suite *TestSuite) TestNoArgument() {

	os.Args = []string{"filesize"}

	err := FileSize(os.Args)
	assert.EqualError(suite.T(), err, "failed to find location of files, no argument passed")
}

func (suite *TestSuite) TestFileDoesNotExist() {

	os.Args = []string{"filesize", "somefile"}

	err := FileSize(os.Args)

	assert.EqualError(suite.T(), err, "open somefile: no such file or directory")
}

// Test the size of the file returned from the function
func (suite *TestSuite) TestGetFileSize() {
	fileContent := "some text!"

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := w.Write([]byte(fileContent))
		assert.NoError(suite.T(), err)
	}))
	defer ts.Close()

	fileLocation := ts.URL + "/A352744B-2CB4-4738-B6B5-BA55D25FB469/some/file.c4gh"
	size, err := getFileSize(fileLocation)

	assert.Equal(suite.T(), int64(10), size)
	assert.NoError(suite.T(), err)
}

func (suite *TestSuite) TestGetFileSizeFail() {

	fileLocation := "http://url/to/file/A352744B-2CB4-4738-B6B5-BA55D25FB469/some/file.c4gh"
	size, err := getFileSize(fileLocation)

	assert.True(suite.T(), strings.HasPrefix(err.Error(), "failed to head file, reason:"))
	assert.Equal(suite.T(), int64(0), size)
}
