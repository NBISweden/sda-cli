package htsget

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/NBISweden/sda-cli/helpers"
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
var DatasetID = Args.String("datasetID", "", "Dataset ID for the file to download")
var FileName = Args.String("fileName", "", "The name of the file to download")
var configPath = Args.String("config", "",
	"S3 config file to use for uploading.")

type htsgetResponse struct {
	Htsget struct {
		Format string `json:"format"`
		Urls   []struct {
			URL     string `json:"url"`
			Headers struct {
				Range          string `json:"Range"`
				UserAgent      string `json:"user-agent"`
				Host           string `json:"host"`
				AcceptEncoding string `json:"accept-encoding"`
				Authorization  string `json:"authorization"`
			} `json:"headers,omitempty"`
		} `json:"urls"`
	} `json:"htsget"`
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
	if len(arguments) != 2 {
		return fmt.Errorf("failed to find location of files, no argument passed")
	}

	// var currentPath, urlsFilePath string
	// currentPath, err = os.Getwd()
	// if err != nil {
	// 	return fmt.Errorf("failed to get current path, reason: %v", err)
	// }
	datasetID := arguments[0]
	fileName := arguments[1]

	config, err := helpers.GetAuth(*configPath)
	if err != nil {
		return err
	}
	// TODO: Add cases for different type of files
	// i.e. bam files require the /reads/, replace for vcf
	url := config.HTSGetHost + "/reads/" + datasetID + "/" + fileName

	method := "GET"

	client := &http.Client{}
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		fmt.Println(err)
		return fmt.Errorf("failed to make request, reason: %v", err)
	}

	req.Header.Add("Authorization", "Bearer "+config.AccessToken)

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

	var htsgetURLs htsgetResponse
	err = json.Unmarshal(body, &htsgetURLs)
	if err != nil {
		return fmt.Errorf("error unmarshaling response, reason: %v", err)
	}

	fmt.Println(htsgetURLs.Htsget.Urls[0].URL)
	err = downloadFiles(htsgetURLs, config)
	if err != nil {
		return fmt.Errorf("error downloading the files, reason: %v", err)
	}
	return nil

}

func downloadFiles(htsgeURLs htsgetResponse, config *helpers.Config) (err error) {

	for index, _ := range htsgeURLs.Htsget.Urls {
		url := htsgeURLs.Htsget.Urls[index].URL
		if strings.Contains(url, "data:;") {
			continue
		}
		method := "GET"

		client := &http.Client{}
		req, err := http.NewRequest(method, url, nil)
		if err != nil {
			fmt.Println(err)
			return fmt.Errorf("failed to make request, reason: %v", err)
		}

		req.Header.Add("Authorization", "Bearer "+config.AccessToken)

		var currentPath string
		currentPath, err = os.Getwd()
		if err != nil {
			return fmt.Errorf("failed to get current path, reason: %v", err)
		}

		res, err := client.Do(req)
		if err != nil {
			fmt.Println(err)
			return fmt.Errorf("failed to do the request, reason: %v", err)
		}
		defer res.Body.Close()

		// Create the file in the current location
		// Get the filename from the URL
		out, err := os.Create(currentPath + url[strings.LastIndex(url, "/"):])
		if err != nil {
			return err
		}
		defer out.Close()

		// Write the body to file
		_, err = io.Copy(out, res.Body)
		if err != nil {
			fmt.Printf("error copying the file, %v", err)
			return err
		}
	}

	return nil

}
