package download

import (
	"io"
	"log"
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

	urlsListPath, err := os.CreateTemp(os.TempDir(), "urls_list-")
	assert.NoError(suite.T(), err)
	defer os.Remove(urlsListPath.Name())

	_, err = GetURLsFile(urlsListPath.Name())
	assert.EqualError(suite.T(), err, "failed to get list of files, empty file")
}

func (suite *TestSuite) TestCorrectUrlsFile() {

	urlsListFile := `someUrlToFile1
someUrlToFile2
someUrlToFile3
`

	urlsListPath, err := os.CreateTemp(os.TempDir(), "urls_list-")
	assert.NoError(suite.T(), err)
	defer os.Remove(urlsListPath.Name())

	err = os.WriteFile(urlsListPath.Name(), []byte(urlsListFile), 0600)
	if err != nil {
		log.Printf("failed to write temp config file, %v", err)
	}

	urlsList, err := GetURLsFile(urlsListPath.Name())
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

// Test that the get request doesn't return an error when the server returns 200
func (suite *TestSuite) TestDownloadFile() {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	file := "somefile.c4gh"
	err := downloadFile(ts.URL, file)
	assert.NoError(suite.T(), err)

	// Remove the file created from the downloadFile function
	_ = os.Remove(file)
}

// Test that the get returns an error when response code is >=400 and that
// the error is parsed correctly when the S3 backend response is in xml
func (suite *TestSuite) TestdownloadFileErrorStatusCode() {

	file := "somefile.c4gh"

	// Case when the user tried to download from a private bucket
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(w, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<Error><Code>NoSuchKey</Code><Message>The specified key does not exist.</Message><Key>A352764B-2KB4-4738-B6B5-BA55D25FB469</Key><BucketName>download</BucketName><Resource>/download/A352764B-2KB4-4738-B6B5-BA55D25FB469</Resource><RequestId>1728F10EAA85663B</RequestId><HostId>73e4c710-46e8-4846-b70b-86ee905a3ab0</HostId></Error>")
	}))
	defer ts.Close()

	err := downloadFile(ts.URL, file)
	assert.EqualError(suite.T(), err, "request failed with `404 Not Found`, details: {Code:NoSuchKey Message:The specified key does not exist. Resource:/download/A352764B-2KB4-4738-B6B5-BA55D25FB469}")

	// Case when the user tried to download from a private bucket
	ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<Error><Code>AllAccessDisabled</Code><Message>All access to this bucket has been disabled.</Message><Resource>/minio/test/dummy/data_file1.c4gh</Resource><RequestId></RequestId><HostId>73e4c710-46e8-4846-b70b-86ee905a3ab0</HostId></Error>")
	}))
	defer ts.Close()

	err = downloadFile(ts.URL, file)
	assert.EqualError(suite.T(), err, "request failed with `403 Forbidden`, details: {Code:AllAccessDisabled Message:All access to this bucket has been disabled. Resource:/minio/test/dummy/data_file1.c4gh}")

	// Check that the downloadFile function did not create any file in case of error
	_, err = os.Stat(file)
	assert.EqualError(suite.T(), err, "stat somefile.c4gh: no such file or directory")
}

func (suite *TestSuite) TestCreateFilePath() {

	fileName := "https://some/base/A352744B-2CB4-4738-B6B5-BA55D25FB469/some/file.txt"
	baseDir := "one/directory"

	path, err := createFilePathFromURL(fileName, baseDir)
	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), path, "one/directory/some/file.txt")

	_, err = os.Stat(baseDir)
	assert.NoError(suite.T(), err)

	err = os.RemoveAll("one")
	assert.NoError(suite.T(), err)
}

func (suite *TestSuite) TestGetURLsListFile() {

	currentPath, err := os.Getwd()
	assert.NoError(suite.T(), err)

	// Folder URL does not exist
	fileLocation := "https://some/base/A352744B-2CB4-4738-B6B5-BA55D25FB469/some/"

	urlsFilePath, err := GetURLsListFile(currentPath, fileLocation)
	assert.Equal(suite.T(), urlsFilePath, "")
	// The error differs locally and in the repo, therefore checking that error starts
	// with the specified phrase instead of the whole message
	assert.True(suite.T(), strings.HasPrefix(err.Error(), "failed to download file, reason:"))

	// File URL does not exist
	fileLocation = "https://some/base/A352744B-2CB4-4738-B6B5-BA55D25FB469/some/urls_list.txt"

	urlsFilePath, err = GetURLsListFile(currentPath, fileLocation)
	assert.Equal(suite.T(), urlsFilePath, "")
	// The error differs locally and in the repo, therefore checking that error starts
	// with the specified phrase instead of the whole message
	assert.True(suite.T(), strings.HasPrefix(err.Error(), "failed to download file, reason:"))

	// File path
	fileLocation = "some/path/to/urls_list.txt"
	urlsFilePath, err = GetURLsListFile(currentPath, fileLocation)
	assert.Equal(suite.T(), urlsFilePath, fileLocation)
	assert.NoError(suite.T(), err)
}

func (suite *TestSuite) TestGetURLsListFilePass() {
	urlsList := `http://url/to/file1.c4gh
http://url/to/file2.c4gh
http://url/to/file3.c4gh
`

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := w.Write([]byte(urlsList))
		assert.NoError(suite.T(), err)
	}))
	defer ts.Close()

	file, err := os.Getwd()
	if err != nil {
		log.Printf("failed to get current directory, %v", err)
	}

	// Testing with url containing the file
	fileLocation := ts.URL + "/A352744B-2CB4-4738-B6B5-BA55D25FB469/some/urls_list.txt"
	urlsFilePath, err := GetURLsListFile(file, fileLocation)
	assert.NoError(suite.T(), err)
	// Check that the file exists
	_, err = os.Stat(urlsFilePath)
	assert.NoError(suite.T(), err)

	// Check that the file contains the correct urls
	expectedUrls, err := os.ReadFile(urlsFilePath)
	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), expectedUrls, []byte(urlsList))

	// Remove the file created from the downloadFile function
	_ = os.Remove(urlsFilePath)

	// Testing with the URL containing the file folder
	fileLocation = ts.URL + "/A352744B-2CB4-4738-B6B5-BA55D25FB469/some/"
	urlsFilePath, err = GetURLsListFile(file, fileLocation)
	assert.NoError(suite.T(), err)

	// Check that the file exists
	_, err = os.Stat(urlsFilePath)
	assert.NoError(suite.T(), err)

	// Check that the file contains the correct urls
	expectedUrls, err = os.ReadFile(urlsFilePath)
	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), expectedUrls, []byte(urlsList))

	// Remove the file created from the downloadFile function
	_ = os.Remove(urlsFilePath)

}
