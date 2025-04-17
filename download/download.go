package download

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
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
Usage: %s [-config <config-file>] download [OPTIONS] [ARGUMENTS]

Download files from the Sensitive Data Archive (SDA) using APIs at the
specified URL. The user must have the necessary access rights (visas) to the
datasets being downloaded.

Important:
  Provide exactly one of the following options to specify files to download:
    - [filepath(s) or fileid(s)] 
    - -dataset
    - -recursive <dirpath>
    - -from-file <list-filepath>

Global options:
  -config <config-file>       Path to the configuration file. 
  
Required options: 
  -dataset-id <datasetID>     Dataset ID for the file(s) to download.
  -url <uri>                  The url of the download server.

Optional options:
  -pubkey <public-key-file>   Key to use for encrypting downloaded files server-side.
                              This key must be given here or in the config file.
  -outdir <dir>               Directory to save the downloaded files.
                              If not specified, files will be saved in the current directory.
  -dataset                    Download all files in the dataset specified by '-dataset-id'.
  -recursive <dirpath>        Download all files recursively from the given directory path.
  -from-file <list-filepath>  Download all files listed in the specified file.

Arguments:
  [filepath(s)]          Specific file paths to download.
  [fileid(s)]            File IDs of files to download.`

// Args is a flagset that needs to be exported so that it can be written to the
// main program help
var Args = flag.NewFlagSet("download", flag.ContinueOnError)

var datasetID = Args.String("dataset-id", "", "Dataset ID for the file to download.")

var URL = Args.String("url", "", "The url of the download server.")

var outDir = Args.String("outdir", "", "Directory for downloaded files.")

var datasetdownload = Args.Bool("dataset", false, "Download all the files of the dataset.")

var pubKeyPath = Args.String("pubkey", "",
	"Public key file to use for encryption of files to download.")

var recursiveDownload = Args.Bool("recursive", false, "Download content of the folder.")

var fromFile = Args.Bool("from-file", false, "Download files from file list.")

var pubKeyBase64 string

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

// Download function downloads files from the SDA by using the
// download's service APIs
func Download(args []string, configPath string) error {
	// Call ParseArgs to take care of all the flag parsing
	err := helpers.ParseArgs(args, Args)
	if err != nil {
		return fmt.Errorf("failed parsing arguments, reason: %v", err)
	}

	if *datasetID == "" || *URL == "" || configPath == "" {
		return fmt.Errorf("missing required arguments, dataset-id, config and url are required")
	}

	// Check if both -recursive and -dataset flags are set
	if *recursiveDownload && *datasetdownload {
		return fmt.Errorf("both -recursive and -dataset flags are set, choose one of them")
	}

	// Check that file(s) are not missing if the -dataset flag is not set
	if len(Args.Args()) == 0 && !*datasetdownload {
		if !*recursiveDownload {
			return fmt.Errorf("no files provided for download")
		}

		return fmt.Errorf("no folders provided for recursive download")
	}

	// Check if -dataset flag is set and files are provided
	if *datasetdownload && len(Args.Args()) > 0 {
		return fmt.Errorf(
			"files provided with -dataset flag, add either the flag or the file(s), not both",
		)
	}

	// Check if -from-file flag is set and only one file is provided
	if *fromFile && len(Args.Args()) != 1 {
		return fmt.Errorf(
			"one file should be provided with the -from-file flag",
		)
	}

	// Get the configuration file or the .sda-cli-session
	config, err := helpers.GetAuth(configPath)
	if err != nil {
		return err
	}

	// Check if the token has expired
	err = helpers.CheckTokenExpiration(config.AccessToken)
	if err != nil {
		return err
	}
	pubKeyBase64, err = helpers.GetPublicKey64(pubKeyPath)
	if err != nil {
		return err
	}

	// print the host_base for the user
	helpers.PrintHostBase(config.HostBase)

	switch {
	// Case where the user is setting the -dataset flag
	// then download all the files in the dataset.
	// Case where the user is setting the -recursive flag
	// then download the content of the path
	// Case where the user is setting the -from-file flag
	// then download the files from the file list
	// Default case, download the provided files.
	case *datasetdownload:
		err = datasetCase(config.AccessToken)
		if err != nil {
			return err
		}
	case *recursiveDownload:
		err = recursiveCase(config.AccessToken)
		if err != nil {
			return err
		}
	case *fromFile:
		err = fileCase(config.AccessToken, true)
		if err != nil {
			return err
		}
	default:
		err = fileCase(config.AccessToken, false)
		if err != nil {
			return err
		}
	}

	return nil
}

func datasetCase(token string) error {
	fmt.Println("Downloading all files in the dataset")
	files, err := GetFilesInfo(*URL, *datasetID, "", token)
	if err != nil {
		return err
	}
	// Loop through the files and download them
	for _, file := range files {
		// Download URL for the file
		fileURL := *URL + "/s3/" + file.DatasetID + "/" + file.FilePath
		if err != nil {
			return err
		}
		err = downloadFile(fileURL, token, pubKeyBase64, file.FilePath)
		if err != nil {
			return err
		}
	}

	return nil
}

func recursiveCase(token string) error {
	fmt.Println("Downloading content of the path(s)")
	// get all the files of the dataset
	files, err := GetFilesInfo(*URL, *datasetID, "", token)
	if err != nil {
		return err
	}
	// check all the provided paths and add a slash
	// to each one of them if does not exist and
	// append them in a slice
	var dirPaths []string
	for _, path := range Args.Args() {
		if !strings.HasSuffix(path, "/") {
			path += "/"
		}
		dirPaths = append(dirPaths, path)
	}
	var missingPaths []string
	// Loop over all the files of the dataset and
	// check if the provided path is part of their filepath.
	// If it is then download the file
	for _, dirPath := range dirPaths {
		pathExists := false
		for _, file := range files {
			if strings.Contains(file.FilePath, dirPath) {
				pathExists = true
				fileURL := *URL + "/s3/" + file.DatasetID + "/" + file.FilePath
				err = downloadFile(fileURL, token, pubKeyBase64, file.FilePath)
				if err != nil {
					return err
				}
			}
		}
		// If dirPath does not exist add in the list
		if !pathExists {
			missingPaths = append(missingPaths, dirPath)
		}
	}
	// If all the given paths do not exist then return an error
	if len(missingPaths) == len(dirPaths) {
		return errors.New("given path(s) do not exist")
	}
	// If some of the give paths do not exist then just return a message
	if len(missingPaths) > 0 {
		for _, missingPath := range missingPaths {
			fmt.Println("Non existing path: ", missingPath)
		}
	}

	return nil
}

func fileCase(token string, fileList bool) error {
	var files []string
	if fileList {
		// get the files from the file list
		fmt.Println("Downloading files from file list")
		fileList, err := GetURLsFile(Args.Args()[0])
		if err != nil {
			return err
		}
		files = append(files, fileList...)
	} else {
		// get the files from the arguments
		fmt.Println("Downloading files")
		files = append(files, Args.Args()...)
	}

	// Loop through the files and download them
	for _, filePath := range files {
		fileIDURL, apiFilePath, err := getFileIDURL(*URL, token, pubKeyBase64, *datasetID, filePath)
		if err != nil {
			return err
		}

		err = downloadFile(fileIDURL, token, pubKeyBase64, apiFilePath)
		if err != nil {
			return err
		}
	}

	return nil
}

// downloadFile downloads the file by using the download URL
func downloadFile(uri, token, pubKeyBase64, filePath string) error {
	outFilename := filePath
	if *outDir != "" {
		outFilename = *outDir + "/" + filePath
	}

	filePath = strings.TrimSuffix(outFilename, ".c4gh")

	// Get the file body
	body, err := getResponseBody(uri, token, pubKeyBase64)
	if err != nil {
		return fmt.Errorf("failed to get file for download, reason: %v", err)
	}

	// Create the directory if it does not exist
	fileDir := filepath.Dir(filePath)
	err = os.MkdirAll(fileDir, os.ModePerm)
	if err != nil {
		return fmt.Errorf("failed to create directory, reason: %v", err)
	}

	if pubKeyBase64 != "" {
		filePath += ".c4gh"
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
// and returns the download URL for the file and the filepath from the API response
func getFileIDURL(baseURL, token, pubKeyBase64, dataset, filename string) (string, string, error) {
	// Get the files of the dataset
	datasetFiles, err := GetFilesInfo(baseURL, dataset, pubKeyBase64, token)
	if err != nil {
		return "", "", err
	}

	// Get the file ID for the filename
	var idx int
	switch {
	case strings.Contains(filename, "/"):
		// If filename does not have a crypt4gh suffix, add one
		if !strings.HasSuffix(filename, ".c4gh") {
			filename += ".c4gh"
		}
		idx = slices.IndexFunc(
			datasetFiles,
			func(f File) bool { return strings.Contains(f.FilePath, filename) },
		)
	default:
		idx = slices.IndexFunc(
			datasetFiles,
			func(f File) bool { return strings.Contains(f.FileID, filename) },
		)
	}

	if idx == -1 {
		return "", "", fmt.Errorf("File not found in dataset %s", filename)
	}

	url := baseURL + "/s3/" + dataset + "/" + datasetFiles[idx].FilePath

	return url, datasetFiles[idx].FilePath, nil
}

func GetDatasets(baseURL, token string) ([]string, error) {
	// Sanitize the base_url
	u, err := url.ParseRequestURI(baseURL)
	if err != nil || u.Scheme == "" {
		return []string{}, fmt.Errorf("invalid base URL")
	}
	// Make the url for listing datasets
	datasetsURL := baseURL + "/metadata/datasets"
	// Get the response body from the datasets API
	allDatasets, err := getResponseBody(datasetsURL, token, "")
	if err != nil {
		return []string{}, fmt.Errorf("failed to get datasets, reason: %v", err)
	}
	// Parse the JSON response
	var datasets []string
	err = json.Unmarshal(allDatasets, &datasets)
	if err != nil {
		return []string{}, fmt.Errorf("failed to parse dataset list JSON, reason: %v", err)
	}

	return datasets, nil
}

// GetFilesInfo gets the files of the dataset by using the dataset ID
func GetFilesInfo(baseURL, dataset, pubKeyBase64, token string) ([]File, error) {
	// Sanitize the base_url
	u, err := url.ParseRequestURI(baseURL)
	if err != nil || u.Scheme == "" {
		return []File{}, fmt.Errorf("invalid base URL")
	}
	// Make the url for listing files
	filesURL := baseURL + "/metadata/datasets/" + dataset + "/files"
	// Get the response body from the files API
	allFiles, err := getResponseBody(filesURL, token, pubKeyBase64)
	if err != nil {
		return []File{}, fmt.Errorf("failed to get files, reason: %v", err)
	}
	// Parse the JSON response
	var files []File
	err = json.Unmarshal(allFiles, &files)
	if err != nil {
		return []File{}, fmt.Errorf("failed to parse file list JSON, reason: %v", err)
	}

	return files, nil
}

// getBody gets the body of the response from the URL
func getBody(url, token, pubKeyBase64 string) ([]byte, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request, reason: %v", err)
	}

	// Add headers
	req.Header.Add("Authorization", "Bearer "+token)
	req.Header.Add("Content-Type", "application/json")
	if pubKeyBase64 != "" {
		req.Header.Add("Client-Public-Key", pubKeyBase64)
	}

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
