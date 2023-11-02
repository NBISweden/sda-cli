package htsget

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/NBISweden/sda-cli/helpers"
	log "github.com/sirupsen/logrus"
)

// Help text and command line flags.

// Usage text that will be displayed as command line help text when using the
// `help download` command
var Usage = `
USAGE: %s htsget (-outdir <dir>) [url | file]

download:
    Downloads files from the Sensitive Data Archive (SDA).  A list with
    URLs for files to download must be provided either as a URL directly
    to a remote url_list.txt file or to its containing directory
    (ending with "/"). Alternatively, the local path to such a file may
    be given, instead.  The files will be downloaded in the current
    directory, if outdir is not defined and their folder structure is
    preserved.
`

// ArgHelp is the suffix text that will be displayed after the argument list in
// the module help
var ArgHelp = `
    [urls]
        All flagless arguments will be used as download URLs.`

// Args is a flagset that needs to be exported so that it can be written to the
// main program help
var Args = flag.NewFlagSet("htsget", flag.ExitOnError)
var datasetID = Args.String("datasetID", "", "Dataset ID for the file to download")
var fileName = Args.String("fileName", "", "The name of the file to download")

// Gets the file name for a URL, using regex
func createFilePathFromURL(file string, baseDir string) (fileName string, err error) {
	// Create the file path according to the way files are stored in S3
	// The folder structure comes after the UID described in the regex
	re := regexp.MustCompile(`(?i)[0-9a-z]{8}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{12}/(.*)`)
	match := re.FindStringSubmatch(file)
	if match == nil || len(match) < 1 {
		return fileName, fmt.Errorf("failed to parse url for downloading file")
	}
	if baseDir != "" && !strings.HasSuffix(baseDir, "/") {
		baseDir += "/"
	}
	fileName = filepath.Join(baseDir, match[1])

	var filePath string
	if strings.Contains(fileName, string(os.PathSeparator)) {
		filePath = filepath.Dir(fileName)
		err = os.MkdirAll(filePath, os.ModePerm)
		if err != nil {
			return fileName, err
		}
	}

	return fileName, nil
}

// Downloads a file from the url to the filePath location
func downloadFile(url string, filePath string) error {

	// Get the file from the provided url
	resp, err := http.Get(url)
	if err != nil {
		return fmt.Errorf("failed to download file, reason: %v", err)
	}
	defer resp.Body.Close()

	// Check reponse status and report S3 error response
	if resp.StatusCode >= 400 {
		errorDetails, err := helpers.ParseS3ErrorResponse(resp.Body)
		if err != nil {
			log.Error(err.Error())
		}

		return fmt.Errorf("request failed with `%s`, details: %v", resp.Status, errorDetails)
	}

	// Create the file in the current location
	out, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer out.Close()

	// Write the body to file
	_, err = io.Copy(out, resp.Body)
	defer out.Close()

	return err

}

// GetURLsFile reads the urls_list.txt file and returns the urls of the files in a list
func GetURLsFile(urlsFilePath string) (urlsList []string, err error) {

	urlsFile, err := os.Open(filepath.Clean(urlsFilePath))
	if err != nil {
		return nil, err
	}
	defer urlsFile.Close()

	scanner := bufio.NewScanner(urlsFile)
	for scanner.Scan() {
		urlsList = append(urlsList, scanner.Text())
	}
	if len(urlsList) == 0 {
		return urlsList, fmt.Errorf("failed to get list of files, empty file")
	}

	return urlsList, scanner.Err()
}

// GetURLsListFile is returning the path to the urls_list.txt by handling the URL
// or path provided by the user. In case of a URL, the file is downloaded in the
// current path
func GetURLsListFile(currentPath string, fileLocation string) (urlsFilePath string, err error) {
	switch {
	// Case where the user passes the url to the s3 folder where the data exists
	// Download the urls_list.txt file first and then the data files
	// e.g. https://some/url/to/folder/
	case strings.HasSuffix(fileLocation, "/") && regexp.MustCompile(`https?://`).MatchString(fileLocation):
		urlsFilePath = currentPath + "/urls_list.txt"
		err = downloadFile(fileLocation+"urls_list.txt", urlsFilePath)
		if err != nil {
			return "", err
		}
	// Case where the user passes the url directly to urls_list.txt
	// e.g. https://some/url/to/urls_list.txt
	case regexp.MustCompile(`https?://`).MatchString(fileLocation):
		urlsFilePath = currentPath + "/urls_list.txt"
		err = downloadFile(fileLocation, urlsFilePath)
		if err != nil {
			return "", err
		}
	// Case where the user passes a file containg the urls to download
	// e.g. /some/folder/to/file.txt
	default:
		urlsFilePath = fileLocation
	}

	return urlsFilePath, nil
}

// Htsget function downloads the files included in the urls_list.txt file.
// The argument can be a local file or a url to an S3 folder
func Htsget(args []string) error {

	// Call ParseArgs to take care of all the flag parsing
	err := helpers.ParseArgs(args, Args)
	if err != nil {
		return fmt.Errorf("failed parsing arguments, reason: %v", err)
	}

	// Args() returns the non-flag arguments, which we assume are filenames.
	arguments := Args.Args()
	if len(arguments) == 0 {
		return fmt.Errorf("failed to find location of files, no argument passed")
	}

	// var currentPath, urlsFilePath string
	// currentPath, err = os.Getwd()
	// if err != nil {
	// 	return fmt.Errorf("failed to get current path, reason: %v", err)
	// }

	url := "http://localhost:8088/reads/EGAD74900000101/NA12878"
	method := "GET"

	client := &http.Client{}
	req, err := http.NewRequest(method, url, nil)

	if err != nil {
		fmt.Println(err)
		return fmt.Errorf("failed to make request, reason: %v", err)
	}
	req.Header.Add("Authorization", "Bearer eyJqa3UiOiJodHRwczovL29pZGM6ODA4MC9qd2siLCJraWQiOiJFQzEiLCJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJyZXF1ZXN0ZXJAZGVtby5vcmciLCJhdWQiOlsiYXVkMSIsImF1ZDIiXSwiYXpwIjoiYXpwIiwic2NvcGUiOiJvcGVuaWQgZ2E0Z2hfcGFzc3BvcnRfdjEiLCJpc3MiOiJodHRwczovL29pZGM6ODA4MC8iLCJleHAiOjk5OTk5OTk5OTksImlhdCI6MTU2MTYyMTkxMywianRpIjoiNmFkN2FhNDItM2U5Yy00ODMzLWJkMTYtNzY1Y2I4MGMyMTAyIn0.yj8Qr-AqD_NxfsNcZRSZxnDAe9Vx3oMxRi8zJyeXk9GPTfBRnPb1AH-660NFrCw5xa3mhZe1agNtQtU8xtilgQ")

	res, err := client.Do(req)
	if err != nil {
		fmt.Println(err)
		return fmt.Errorf("failed to do the request, reason: %v", err)
	}
	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		fmt.Println(err)
		return fmt.Errorf("failed to read response, reason: %v", err)
	}
	fmt.Println(string(body))

	return nil

}
