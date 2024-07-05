package sdadownload

import (
	"encoding/base64"
	"encoding/json"
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
USAGE: %s sda-download -config <s3config-file> -dataset-id <datasetID> -url <uri> (--pubkey <public-key-file>) (-outdir <dir>) ([filepath(s)] or --dataset or --recursive <dirpath>)

sda-download:
	Downloads files from the Sensitive Data Archive (SDA) by using APIs from the given url. The user
	must have been granted access to the datasets (visas) that are to be downloaded.
	The files will be downloaded in the current directory, if outdir is not defined.
	When the -pubkey flag is used, the downloaded files will be server-side encrypted with the given public key.
    If the --dataset flag is used, all files in the dataset will be downloaded.
    If the --recursive flag is used, all files in the directory will be downloaded.
    `

// ArgHelp is the suffix text that will be displayed after the argument list in
// the module help
var ArgHelp = `
	[datasetID]
		The ID of the dataset that the file is part of.
	[uri]
		All flagless arguments will be used as sda-download uri.
	[filepath(s)]
		The filepath of the file to download. If no filepath is provided
        then the whole dataset will be downloaded.
    [dirpath]
        The directory path to download all files recursively.`

// Args is a flagset that needs to be exported so that it can be written to the
// main program help
var Args = flag.NewFlagSet("sda-download", flag.ExitOnError)

var configPath = Args.String("config", "", "S3 config file to use for downloading.")

var datasetID = Args.String("dataset-id", "", "Dataset ID for the file to download.")

var URL = Args.String("url", "", "The url of the sda-download server.")

var outDir = Args.String("outdir", "", "Directory for downloaded files.")

var datasetdownload = Args.Bool("dataset", false, "Download all the files of the dataset.")

var pubKeyPath = Args.String("pubkey", "",
	"Public key file to use for encryption of files to download.")

var recursiveDownload = Args.Bool("recursive", false, "Download content of the folder.")

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
	// Call ParseArgs to take care of all the flag parsing
	err := helpers.ParseArgs(args, Args)
	if err != nil {
		return fmt.Errorf("failed parsing arguments, reason: %v", err)
	}

	if *datasetID == "" || *URL == "" || *configPath == "" {
		return fmt.Errorf("missing required arguments, dataset, config and url are required")
	}

	// Check if both --recursive and --dataset flags are set
	if *recursiveDownload && *datasetdownload {
		return fmt.Errorf("both --recursive and --dataset flags are set, choose one of them")
	}

	// Check that file(s) are not missing if the --dataset flag is not set
	if len(Args.Args()) == 0 && !*datasetdownload {
		if !*recursiveDownload {
			return fmt.Errorf("no files provided for download")
		} else {
			return fmt.Errorf("no folders provided for recursive download")
		}
	}

	// Check if --dataset flag is set and files are provided
	if *datasetdownload && len(Args.Args()) > 0 {
		return fmt.Errorf(
			"files provided with --dataset flag, add either the flag or the file(s), not both",
		)
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

	// Check if dataset flag is set
	// If it is, download all files in the dataset
	// If it is not, download the files that are provided
	if *datasetdownload {
		err = datasetCase(config.AccessToken)
		if err != nil {
			return err
		}
	} else {
		err = fileCase(config.AccessToken)
		if err != nil {
			return err
		}
	}

	return nil
}

func datasetCase(token string) error {
	fmt.Println("Downloading all files in the dataset")
	files, err := getFilesInfo(*URL, *datasetID, "", token)
	if err != nil {
		return err
	}
	// Loop through the files and download them
	for _, file := range files {
		// Download URL for the file
		fileURL := *URL + "/files/" + file.FileID
		err = downloadFile(fileURL, token, "", file.FilePath)
		if err != nil {
			return err
		}
	}

	return nil
}

func fileCase(token string) error {
	fmt.Println("Downloading files")
	// Get the files from the arguments
	var files []string
	files = append(files, Args.Args()...)

	*pubKeyPath = strings.TrimSpace(*pubKeyPath)
	var pubKeyBase64 string
	if *pubKeyPath != "" {
		// Read the public key
		pubKey, err := os.ReadFile(*pubKeyPath)
		if err != nil {
			return fmt.Errorf("failed to read public key, reason: %v", err)
		}
		pubKeyBase64 = base64.StdEncoding.EncodeToString(pubKey)
	}

	// Loop through the files and download them
	for _, filePath := range files {
		fileIDURL, err := getFileIDURL(*URL, token, pubKeyBase64, *datasetID, filePath)
		if err != nil {
			return err
		}

		err = downloadFile(fileIDURL, token, pubKeyBase64, filePath)
		if err != nil {
			return err
		}
	}

	return nil
}

// downloadFile downloads the file by using the download URL
func downloadFile(uri, token, pubKeyBase64, filePath string) error {
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
// and returns the download URL for the file
func getFileIDURL(baseURL, token, pubKeyBase64, dataset, filename string) (string, error) {
	// Get the files of the dataset
	datasetFiles, err := getFilesInfo(baseURL, dataset, pubKeyBase64, token)
	if err != nil {
		return "", err
	}
	// Get the file ID for the filename
	var idx int
	switch {
	case strings.Contains(filename, "/"):
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
		return "", fmt.Errorf("File not found in dataset %s", filename)
	}

	var url string
	// If no public key is provided, retrieve the unencrypted file
	if pubKeyBase64 == "" {
		url = baseURL + "/files/" + datasetFiles[idx].FileID
	} else {
		url = baseURL + "/s3-encrypted/" + dataset + "/" + filename
	}

	return url, nil
}

// getFilesInfo gets the files of the dataset by using the dataset ID
func getFilesInfo(baseURL, dataset, pubKeyBase64, token string) ([]File, error) {
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
