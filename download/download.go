package download

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

	log "github.com/sirupsen/logrus"
)

// Help text and command line flags.

// Usage text that will be displayed as command line help text when using the
// `help download` command
var Usage = `
USAGE: %s download [url(s)]

Download: Downloads files from the Sensitive Data Archive (SDA). If a directory is
          provided (ending with "/"), then the tool will attempt to first
          download the urls_list.txt file, and then download all files in this
          list. If file urls are given, they will be downloaded as-is.
`

// ArgHelp is the suffix text that will be displayed after the argument list in
// the module help
var ArgHelp = `
  [urls]
        all flagless arguments will be used as download urls.`

// Args is a flagset that needs to be exported so that it can be written to the
// main program help
var Args = flag.NewFlagSet("download", flag.ExitOnError)

// Gets the file name for a URL, using regex
func getFileNameFromURL(file string) (fileName string, err error) {
	// Create the file path according to the way files are stored in S3
	// The folder structure comes after the UID described in the regex
	re := regexp.MustCompile(`[\w\d]{8}-(\w|\d){4}-(\w|\d){4}-(\w|\d){4}-(\w|\d){12}/(.*)`)
	match := re.FindStringSubmatch(file)
	if match == nil || len(match) < 6 {
		return fileName, fmt.Errorf("failed to parse url for downloading file")
	}
	fileName = match[5]

	var filePath string
	if strings.Contains(fileName, "/") {
		filePath = filepath.Dir(fileName)
		err = os.MkdirAll(filePath, os.ModePerm)
		if err != nil {
			return fileName, err
		}
	}

	return fileName, nil
}

// Downloads a file from the url to the filePath location
func downloadListFile(url string, filePath string) error {

	// Get the file from the provided url
	resp, err := http.Get(url)
	if err != nil {
		return fmt.Errorf("failed to download file, reason: %v", err)
	}
	defer resp.Body.Close()

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

// Read the urls_list.txt file and return the urls of the files in a list
func getFilesUrls(urlsFilePath string) (urlsList []string, err error) {

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

// Download function downaloads the files included in the urls_list.txt file.
// The argument can be a local file or a url to an S3 folder
func Download(args []string) error {
	// Parse flags. There are no flags at the moment, but in case some are added
	// we check for them.
	err := Args.Parse(os.Args[1:])
	if err != nil {
		return fmt.Errorf("failed parsing arguments, reason: %v", err)
	}

	// Args() returns the non-flag arguments, which we assume are filenames.
	urls := Args.Args()
	if len(urls) == 0 {
		return fmt.Errorf("failed to find location of files, no argument passed")
	}

	var currentPath, urlsFilePath string
	currentPath, err = os.Getwd()
	if err != nil {
		return fmt.Errorf("failed to get current path, reason: %v", err)
	}

	switch {
	// If the argument ends with "/", download the urls_list.txt file first
	case strings.HasSuffix(urls[0], "/"):
		urlsFilePath = currentPath + "/urls_list.txt"
		err = downloadListFile(urls[0]+"urls_list.txt", urlsFilePath)
		if err != nil {
			return err
		}
	// Case where the user passes the url directly to urls_list.txt
	case strings.Contains(urls[0], "http"):
		urlsFilePath = currentPath + "/urls_list.txt"
		log.Info(urls[0], urlsFilePath)
		err = downloadListFile(urls[0], urlsFilePath)
		if err != nil {
			return err
		}
	// Case where the user passes a file containg the urls to download
	default:
		urlsFilePath = urls[0]
	}

	// Open urls_list.txt file and loop through file urls
	urlsList, err := getFilesUrls(urlsFilePath)
	if err != nil {
		return err
	}

	// Download the files and create the folder structure
	for _, file := range urlsList {

		fileName, err := getFileNameFromURL(file)
		if err != nil {
			return err
		}

		err = downloadListFile(file, fileName)
		if err != nil {
			return err
		}
		log.Infof("downloaded file from url %s", fileName)
	}

	log.Info("finished downloading files from url")

	return nil
}
