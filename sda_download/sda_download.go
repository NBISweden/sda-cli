package sdadownload

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/mail"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/NBISweden/sda-cli/helpers"
	"github.com/vbauerster/mpb/v8"
	"github.com/vbauerster/mpb/v8/decor"
)

// Help text and command line flags.

// Usage text that will be displayed as command line help text when using the
// `help download` command
var Usage = `
USAGE: %s sda-download -config <s3config-file> -dataset <datasetID> -url <uri> (-outdir <dir>) [filepath(s)]

sda-download:
	Downloads files from the Sensitive Data Archive (SDA) by using APIs from the given url. The user
	must have been granted access to the datasets (visas) that are to be downloaded.
	The files will be downloaded in the current directory, if outdir is not defined.
`

// ArgHelp is the suffix text that will be displayed after the argument list in
// the module help
var ArgHelp = `
	[dataset]
		The ID of the dataset that the file is part of.
	[uri]
		All flagless arguments will be used as sda-download uri.
	[filepath(s)]
		The filepath of the file to download.`

// Args is a flagset that needs to be exported so that it can be written to the
// main program help
var Args = flag.NewFlagSet("sda-download", flag.ExitOnError)

var configPath = Args.String("config", "", "S3 config file to use for downloading.")

var datasetID = Args.String("dataset", "", "Dataset ID for the file to download")

var URL = Args.String("url", "", "The url of the sda-download server")

var outDir = Args.String("outdir", "", "Directory for downloaded files.")

// necessary for mocking in testing
var getResponseBody = getBody

// File struct represents the file metadata
type File struct {
	FileID                    string `json:"fileId"`
	DatasetID                 string `json:"datasetId"`
	DisplayFileName           string `json:"displayFileName"`
	FilePath                  string `json:"filePath"`
	FileName                  string `json:"fileName"`
	FileSize                  int    `json:"fileSize"`
	DecryptedFileSize         int    `json:"decryptedFileSize"`
	DecryptedFileChecksum     string `json:"decryptedFileChecksum"`
	DecryptedFileChecksumType string `json:"decryptedFileChecksumType"`
	FileStatus                string `json:"fileStatus"`
	CreatedAt                 string `json:"createdAt"`
	LastModified              string `json:"lastModified"`
}

// SdaDownload function downloads files from the SDA by using the
// download's service APIs
func SdaDownload(args []string) error {
	var files []string
	// Call ParseArgs to take care of all the flag parsing
	err := helpers.ParseArgs(args, Args)
	if err != nil {
		return fmt.Errorf("failed parsing arguments, reason: %v", err)
	}

	if *datasetID == "" || *URL == "" || *configPath == "" {
		return fmt.Errorf("missing required arguments, dataset, config and url are required")
	}

	// Check that input file/folder list is not empty
	if len(Args.Args()) == 0 {
		return errors.New("no files to download")
	}

	files = append(files, Args.Args()...)

	// Get the configuration file or the .sda-cli-session
	config, err := helpers.GetAuth(*configPath)
	if err != nil {
		return err
	}

	// Check if the token has expired
	err = helpers.CheckTokenExpiration(config.AccessToken)
	if err != nil {
		return err
	}

	// Loop through the files and download them
	for _, filePath := range files {
		fileIDURL, err := getFileIDURL(*URL, config.AccessToken, *datasetID, filePath)
		if err != nil {
			return err
		}

		// Check if the file path contains a userID and if it does,
		// do not keep it in the file path
		filePathSplit := strings.Split(filePath, "/")
		if strings.Contains(filePathSplit[0], "_") {
			_, err := mail.ParseAddress(strings.ReplaceAll(filePathSplit[0], "_", "@"))
			if err == nil {
				filePath = strings.Join(filePathSplit[1:], "/")
			}
		}

		outFilename := filePath
		if *outDir != "" {
			outFilename = *outDir + "/" + filePath
		}

		err = downloadFile(fileIDURL, config.AccessToken, outFilename)
		if err != nil {
			return err
		}
	}

	return nil
}

// downloadFile downloads the file by using the download URL
func downloadFile(uri, token, filePath string) error {
	filePath = strings.TrimSuffix(filePath, ".c4gh")
	// Get the file body
	body, err := getResponseBody(uri, token)
	if err != nil {
		return fmt.Errorf("failed to get file for download, reason: %v", err)
	}

	// Create the directory if it does not exist
	fileDir := filepath.Dir(filePath)
	err = os.MkdirAll(fileDir, os.ModePerm)
	if err != nil {
		return fmt.Errorf("failed to create directory, reason: %v", err)
	}

	outfile, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("failed to create file, reason: %v", err)
	}
	defer outfile.Close()

	// Create a new progress container
	p := mpb.New()

	// Create a new progress bar with the length of the body
	bar := p.AddBar(int64(len(body)),
		mpb.PrependDecorators(
			decor.CountersKibiByte("% .2f / % .2f"),
		),
	)

	// Create a proxy reader
	reader := strings.NewReader(string(body))
	proxyReader := bar.ProxyReader(reader)

	fmt.Printf("Downloading file to %s\n", filePath)
	// Copy from the proxy reader (which updates the progress bar) to the file
	_, err = io.Copy(outfile, proxyReader)
	if err != nil {
		return fmt.Errorf("failed to write file, reason: %v", err)
	}

	// Wait for the progress bar to finish
	p.Wait()

	return nil
}

// getFileIDURL gets the datset files, parses the JSON response to get the file ID
// and returns the download URL for the file
func getFileIDURL(baseURL, token, dataset, filename string) (string, error) {
	// Sanitize the base_url
	u, err := url.ParseRequestURI(baseURL)
	if err != nil || u.Scheme == "" {
		return "", err
	}

	// Make the url for listing files
	filesURL := baseURL + "/metadata/datasets/" + dataset + "/files"

	// Get the response body from the files API
	body, err := getResponseBody(filesURL, token)
	if err != nil {
		return "", fmt.Errorf("failed to get files, reason: %v", err)
	}

	// Parse the JSON response
	var files []File
	err = json.Unmarshal(body, &files)
	if err != nil {
		return "", fmt.Errorf("failed to parse file list JSON, reason: %v", err)
	}

	// Get the file ID for the filename
	var idx int
	switch {
	case strings.Contains(filename, "/"):
		idx = slices.IndexFunc(files, func(f File) bool { return strings.Contains(f.FilePath, filename) })
	default:
		idx = slices.IndexFunc(files, func(f File) bool { return strings.Contains(f.FileID, filename) })
	}

	if idx == -1 {
		return "", fmt.Errorf("File not found in dataset %s", filename)
	}

	return baseURL + "/files/" + files[idx].FileID, nil
}

// getBody gets the body of the response from the URL
func getBody(url, token string) ([]byte, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request, reason: %v", err)
	}

	// Add headers
	req.Header.Add("Authorization", "Bearer "+token)
	req.Header.Add("Content-Type", "application/json")

	// Send the request
	client := &http.Client{}
	res, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get response, reason: %v", err)
	}

	// Check the status code
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("server returned status %d", res.StatusCode)
	}

	// Read the response body
	resBody, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body, reason: %v", err)
	}

	defer res.Body.Close()

	return resBody, nil
}
