package sdadownload

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/NBISweden/sda-cli/helpers"
)

// Help text and command line flags.

// Usage text that will be displayed as command line help text when using the
// `help download` command
var Usage = `
USAGE: %s sda-download -config <s3config-file> -dataset <datasetID> -url <uri> (-outdir <dir>) [filename(s)]

sda-download:
	Downloads files from the Sensitive Data Archive (SDA) by using APIs. The user
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
	[filename]
		The name of the file to download.`

// Args is a flagset that needs to be exported so that it can be written to the
// main program help
var Args = flag.NewFlagSet("sda-download", flag.ExitOnError)

var configPath = Args.String("config", "",
	"S3 config file to use for downloading.")

var datasetID = Args.String("dataset", "",
	"Dataset ID for the file to download")

var url = Args.String("url", "",
	"The name of the file to download")

var outDir = Args.String("outdir", "",
	"Directory for downloaded files.")

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

	if *datasetID == "" || *url == "" || *configPath == "" {
		return fmt.Errorf("missing required arguments, dataset, filename, htsgethost and key are required")
	}

	// Check that input file/folder list is not empty
	if len(Args.Args()) == 0 {
		return errors.New("no files to download")
	}

	for _, fileNames := range Args.Args() {
		files = append(files, fileNames)
	}

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

	for _, file := range files {
		download_url, inbox_path, err := downloadUrl(*url, config.AccessToken, *datasetID, file)
		if err != nil {
			return err
		}

		fmt.Println(download_url)
		fmt.Println(inbox_path)

		inboxPathSplit := strings.Split(inbox_path, "/")
		inboxPath := strings.Join(inboxPathSplit[1:], "/")
		outFilename := inboxPath
		if *outDir != "" {
			outFilename = *outDir + "/" + inboxPath
		}

		err = downloadFile(download_url, config.AccessToken, outFilename)
		if err != nil {
			return err
		}
	}

	return nil
}

func downloadFile(uri, token, filename string) error {
	filename = strings.TrimSuffix(filename, ".c4gh")
	body, err := getBody(uri, token)
	if err != nil {
		return fmt.Errorf("failed to get file for download, reason: %v", err)
	}

	filepath := filepath.Dir(filename)
	err = os.MkdirAll(filepath, os.ModePerm)
	if err != nil {
		return fmt.Errorf("failed to create directory, reason: %v", err)
	}

	// Write the body to file
	err = os.WriteFile(filename, body, 0666)
	if err != nil {
		return fmt.Errorf("failed to write file, reason: %v", err)
	}

	return nil
}

// downloadUrl gets the datset files, parses the JSON response to get the file ID
// and returns the download URL for the file
func downloadUrl(base_url, token, dataset, filename string) (string, string, error) {
	// Sanitize the base_url
	base_url = strings.TrimSuffix(base_url, "/")
	if !strings.HasPrefix(base_url, "https://") {
		base_url = "https://" + base_url
	}

	// Make the url for listing files
	filesUrl := base_url + "/metadata/datasets/" + dataset + "/files"

	// Get the response body from the files API
	body, err := getBody(filesUrl, token)
	if err != nil {
		return "", "", fmt.Errorf("failed to get files, reason: %v", err)
	}

	// Parse the JSON response
	var files []File
	err = json.Unmarshal(body, &files)
	if err != nil {
		return "", "", fmt.Errorf("failed to parse file list JSON, reason: %v", err)
	}

	// Get the file ID for the filename
	fileID := ""
	filePath := ""
	for _, file := range files {
		fmt.Println(file.DisplayFileName)
		if file.DisplayFileName == filename {
			fileID = file.FileID
			filePath = file.FilePath
			break
		}
	}

	if fileID == "" {
		return "", "", fmt.Errorf("failed to find file ID for %s", filename)
	}

	return base_url + "/files/" + fileID, filePath, nil
}

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
