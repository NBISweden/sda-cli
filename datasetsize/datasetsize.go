package datasetsize

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/NBISweden/sda-cli/download"
	"github.com/inhies/go-bytesize"
	log "github.com/sirupsen/logrus"
)

// Help text and command line flags.

// Usage text that will be displayed as command line help text when using the
// `help list` command
var Usage = `
USAGE: %s datasetsize [url(s) | file]

Datasetsize: List files that can be downloaded from the Sensitive Data Archive (SDA).
	  If a URL is provided (ending with "/" or the urls_list.txt file), then the tool 
	  will attempt to first download the urls_list.txt file, and then return a list 
	  of the files with their respective sizes.
`

// ArgHelp is the suffix text that will be displayed after the argument list in
// the module help
var ArgHelp = `
  [url]
        the first flagless argument will be used as file location.`

// Args is a flagset that needs to be exported so that it can be written to the
// main program help
var Args = flag.NewFlagSet("datasetsize", flag.ExitOnError)

// Function to return the size of a file
func getFileSize(file string) (downloadSize int64, err error) {
	resp, err := http.Head(file)
	if err != nil {
		return 0, fmt.Errorf("failed to head file, reason: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("failed to get file, code response not 200")
	}

	size, _ := strconv.Atoi(resp.Header.Get("Content-Length"))
	downloadSize = int64(size)

	return downloadSize, nil
}

// DatasetSize function returns the list of the files available for downloading and their
// respective size. The argument can be a local file or a url to an S3 folder
func DatasetSize(args []string) error {
	// Parse flags. There are no flags at the moment, but in case some are added
	// we check for them.
	err := Args.Parse(args[1:])
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

	urlsFilePath, err = download.GetURLsListFile(currentPath, urls[0])
	if err != nil {
		return fmt.Errorf("failed to get urls list file, reason: %v", err)
	}

	// Open urls_list.txt file and loop through file urls
	urlsList, err := download.GetURLsFile(urlsFilePath)
	if err != nil {
		return err
	}

	var datasetSize float64
	// Get the size for each of the files in the list
	for _, file := range urlsList {

		downloadSize, err := getFileSize(file)
		if err != nil {
			return err
		}
		datasetSize += float64(downloadSize)
		fmt.Printf("%s \t %s \n", bytesize.New(float64(downloadSize)), file[strings.LastIndex(file, "/")+1:])
	}
	fmt.Printf("Total dataset size: %s \n", bytesize.New(datasetSize))

	log.Info("finished listing available files")

	return nil
}
