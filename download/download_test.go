package download

import (
	"io/ioutil"
	"log"
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

func (suite *TestSuite) TestNoArgument() {

	os.Args = []string{"download"}

	err := Download(os.Args)
	assert.EqualError(suite.T(), err, "failed to find location of files, no argument passed")
}

func (suite *TestSuite) TestdownloadFileWrongUrl() {

	url := "someUrl"
	filePath := "."
	err := downloadFile(url, filePath)

	assert.EqualError(suite.T(), err, "failed to download file, reason: Get \"someUrl\": unsupported protocol scheme \"\"")
}

func (suite *TestSuite) TestWrongUrlsFile() {

	urlsListPath, err := ioutil.TempFile(os.TempDir(), "urls_list-")
	assert.NoError(suite.T(), err)
	defer os.Remove(urlsListPath.Name())

	_, err = getURLsFile(urlsListPath.Name())
	assert.EqualError(suite.T(), err, "failed to get list of files, empty file")
}

func (suite *TestSuite) TestCorrectUrlsFile() {

	urlsListFile := `someUrlToFile1
someUrlToFile2
someUrlToFile3
`

	urlsListPath, err := ioutil.TempFile(os.TempDir(), "urls_list-")
	assert.NoError(suite.T(), err)
	defer os.Remove(urlsListPath.Name())

	err = ioutil.WriteFile(urlsListPath.Name(), []byte(urlsListFile), 0600)
	if err != nil {
		log.Printf("failed to write temp config file, %v", err)
	}

	urlsList, err := getURLsFile(urlsListPath.Name())
	assert.NoError(suite.T(), err)

	assert.Equal(suite.T(), 3, len(urlsList))
}

func (suite *TestSuite) TestWronglyFormatterUrls() {

	fileURL := "someURL"

	_, err := createFilePathFromURL(fileURL, "")

	assert.EqualError(suite.T(), err, "failed to parse url for downloading file")
}

func (suite *TestSuite) TestCorrectlyFormatterUrls() {

	fileURL := "https://some/base/A352744B-2CB4-4738-B6B5-BA55D25FB469/some/file.txt"

	_, err := createFilePathFromURL(fileURL, "")
	assert.NoError(suite.T(), err)

	_, err = os.Stat("some")
	assert.NoError(suite.T(), err)

	// Remove the folder created from the createFilePathFromURL function
	_ = os.Remove("some")
}

func (suite *TestSuite) TestCreateFilePath() {

	fileName := "https://some/base/A352744B-2CB4-4738-B6B5-BA55D25FB469/some/file.txt"
	baseDir := "one/directory"

	_, err := createFilePathFromURL(fileName, baseDir)
	assert.NoError(suite.T(), err)

	_, err = os.Stat(baseDir)
	assert.NoError(suite.T(), err)

	err = os.RemoveAll("one")
	assert.NoError(suite.T(), err)
}
