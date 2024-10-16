package htsget

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
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
// `help htsget` command
var Usage = `
USAGE: %s htsget [-dataset <datasetID>] [-filename <filename>] (-reference <referenceName>) [-htsgethost <htsget-hostname>] [-pubkey <public-key-file>] (-output <file>) (--force-overwrite)

htsget:
	Htsget downloads files from the Sensitive Data Archive (SDA), using the
	htsget server. A dataset and a filename must be provided in order to 
	download the file. The files will be downloaded in the current
	directory, if output is not defined.
`

// ArgHelp is the suffix text that will be displayed after the argument list in
// the module help
var ArgHelp = `
    [dataset]
        The ID of the dataset that the file is part of.
    [filename]
        The name of the file to download.
    [reference]
        The reference number of the file to download.
    [host]
        The hostname of the htsget server to use.
    [pubkey]
        The public key file to use for the htsget request.`

// Args is a flagset that needs to be exported so that it can be written to the
// main program help
var Args = flag.NewFlagSet("htsget", flag.ExitOnError)
var datasetID = Args.String("dataset", "", "Dataset ID for the file to download")
var fileName = Args.String("filename", "", "The name of the file to download")
var referenceName = Args.String("reference", "", "The reference number of the file to download")
var htsgetHost = Args.String("host", "", "The host to download from")
var publicKeyFile = Args.String("pubkey", "", "Public key file")
var configPath = Args.String("config", "", "config file.")
var outPut = Args.String("output", "", "Name for the downloaded file.")
var forceOverwrite = Args.Bool("force-overwrite", false, "Force overwrite existing files.")

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
func Htsget(args []string, configPathF string) error {

	// Call ParseArgs to take care of all the flag parsing
	err := helpers.ParseArgs(args, Args)
	if err != nil {
		return fmt.Errorf("failed parsing arguments, reason: %v", err)
	}
	if configPathF == "" {
		configPathF = *configPath
	}

	if *datasetID == "" || *fileName == "" || *htsgetHost == "" || *publicKeyFile == "" {
		return fmt.Errorf("missing required arguments, dataset, filename, host and key are required")
	}

	config, err := helpers.GetAuth(configPathF)
	if err != nil {
		return err
	}

	// read public key from file
	publickey, err := os.ReadFile(*publicKeyFile)
	if err != nil {
		return fmt.Errorf("failed to read public key, reason: %v", err)
	}
	base64publickey := base64.StdEncoding.EncodeToString(publickey)

	// TODO: Add cases for different type of files
	// i.e. bam files require the /reads/, replace for vcf
	url := *htsgetHost + "/reads/" + *datasetID + "/" + *fileName
	if *referenceName != "" {
		url = url + "?referenceName=" + *referenceName
	}
	method := "GET"
	client := &http.Client{}
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		return fmt.Errorf("failed to make request, reason: %v", err)
	}

	req.Header.Add("Authorization", "Bearer "+config.AccessToken)
	req.Header.Add("client-public-key", base64publickey)

	res, err := client.Do(req)

	if err != nil {
		return fmt.Errorf("failed to do the request, reason: %v", err)
	}
	if res.StatusCode != 200 {
		return fmt.Errorf("failed to get the file, status code: %v", res.StatusCode)
	}
	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return fmt.Errorf("failed to read response, reason: %v", err)
	}

	htsgetURLs := htsgetResponse{}
	err = json.Unmarshal(body, &htsgetURLs)
	if err != nil {
		return fmt.Errorf("error unmarshaling response, reason: %v", err)
	}

	err = downloadFiles(htsgetURLs, config)
	if err != nil {
		return fmt.Errorf("error downloading the files, reason: %v", err)
	}

	return nil

}

func downloadFiles(htsgeURLs htsgetResponse, config *helpers.Config) (err error) {

	// Create the directory for the file
	var filePath string
	if err != nil {
		return fmt.Errorf("failed to get current path, reason: %v", err)
	}
	if strings.Contains(*fileName, string(os.PathSeparator)) {
		filePath = filepath.Dir(*fileName)
		err = os.MkdirAll(filePath, os.ModePerm)
		if err != nil {
			return fmt.Errorf("failed to create file path, reason: %v", err)
		}
	}
	filenameToUse := *fileName
	// If output is specified, use it directly without checking for encrypted data
	if *outPut != "" {
		filenameToUse = *outPut
	} else {
		// Check if we have encrypted data to use the right file extension
		for index := range htsgeURLs.Htsget.Urls {
			if strings.Contains(htsgeURLs.Htsget.Urls[index].URL, "base64") {
				filenameToUse = *fileName + ".c4gh"

				break
			}
		}
	}

	if helpers.FileExists(filenameToUse) && !*forceOverwrite {
		return fmt.Errorf("local file already exists, use --force-overwrite to overwrite")
	}
	out, err := os.OpenFile(filenameToUse, os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer out.Close()

	// read public key from file
	publickey, err := os.ReadFile(*publicKeyFile)
	if err != nil {
		deleteFile(out)

		return fmt.Errorf("failed to read public key, reason: %v", err)
	}
	base64publickey := base64.StdEncoding.EncodeToString(publickey)

	for index := range htsgeURLs.Htsget.Urls {
		url := htsgeURLs.Htsget.Urls[index].URL

		// Case for base64 encoded data
		if strings.Contains(url, "data:;") {
			data, err := base64.StdEncoding.DecodeString(strings.SplitAfter(url, "data:;base64,")[1])
			if err != nil {
				deleteFile(out)

				return fmt.Errorf("error decoding the url response, %v", err)
			}
			_, err = io.Copy(out, bytes.NewBuffer(data))
			if err != nil {
				deleteFile(out)

				return fmt.Errorf("error writing the file, %v", err)
			}

			continue
		}

		client := &http.Client{}
		req, err := http.NewRequest(http.MethodGet, url, nil)

		if err != nil {
			deleteFile(out)

			return fmt.Errorf("failed to make request, reason: %v", err)
		}

		req.Header.Add("Authorization", "Bearer "+config.AccessToken)
		req.Header.Add("client-public-key", base64publickey)
		if htsgeURLs.Htsget.Urls[index].Headers.Range != "" {
			req.Header.Add("Range", htsgeURLs.Htsget.Urls[index].Headers.Range)
		}

		res, err := client.Do(req)
		if err != nil {
			deleteFile(out)

			return fmt.Errorf("failed to do the request, reason: %v", err)
		}
		if res.StatusCode != 200 {
			deleteFile(out)

			return fmt.Errorf("failed to get the file, status code: %v", res)
		}
		defer res.Body.Close()

		// Write the body to file
		_, err = io.Copy(out, res.Body)
		if err != nil {
			deleteFile(out)

			return fmt.Errorf("error writing the file, %v", err)
		}

	}
	fmt.Println("File " + out.Name() + " downloaded successfully")

	return nil

}
func deleteFile(f *os.File) {
	name := f.Name()
	// Delete the file created from the downloadFile function
	_ = os.Remove(name)
}
