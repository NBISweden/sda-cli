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
	"strings"

	"github.com/NBISweden/sda-cli/helpers"
)

// Help text and command line flags.

// Usage text that will be displayed as command line help text when using the
// `help htsget` command
var Usage = `
USAGE: %s htsget [-dataset <datasetID>] [-filename <filename>] [-htsgethost <htsget-hostname>] [-key <public-key-file>] (-outdir <dir>)

htsget:
    Htsget downloads files from the Sensitive Data Archive (SDA), using the
	htsget server. A dataset and a filename must be provided in order to 
	download the file. The files will be downloaded in the current
    directory, if outdir is not defined.
`

// ArgHelp is the suffix text that will be displayed after the argument list in
// the module help
var ArgHelp = `
    [datasetID]
        The ID of the dataset that the file is part of.
    [filename]
        The name of the file to download.
	[htsgethost]
		The hostname of the htsget server to use.
	[key]
		The public key file to use for the htsget request.`

// Args is a flagset that needs to be exported so that it can be written to the
// main program help
var Args = flag.NewFlagSet("htsget", flag.ExitOnError)
var DatasetID = Args.String("dataset", "", "Dataset ID for the file to download")
var FileName = Args.String("filename", "", "The name of the file to download")
var HTSGetHost = Args.String("htsgethost", "", "The htsget host to use")
var PublicKeyFile = Args.String("key", "", "Public key file to use for htsget request")
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

	var currentPath string
	currentPath, err = os.Getwd()
	if err != nil {
		return fmt.Errorf("failed to get current path, reason: %v", err)
	}

	fmt.Println("HTSGetHost: ", *HTSGetHost)
	fmt.Println("PublicKeyFile: ", *PublicKeyFile)
	fmt.Println("DatasetID: ", *DatasetID)
	fmt.Println("FileName: ", *FileName)

	config, err := helpers.GetAuth(*configPath)
	if err != nil {
		return err
	}

	// Fix htsget hostname url
	if config.UseHTTPS {
		*HTSGetHost = "https://" + *HTSGetHost
	} else {
		*HTSGetHost = "http://" + *HTSGetHost
	}

	//read public key from file
	publickey, err := os.ReadFile(currentPath + "/" + *PublicKeyFile)
	if err != nil {
		fmt.Println(err)
		return fmt.Errorf("failed to read public key, reason: %v", err)
	}
	base64publickey := base64.StdEncoding.EncodeToString(publickey)

	// TODO: Add cases for different type of files
	// i.e. bam files require the /reads/, replace for vcf
	url := *HTSGetHost + "/reads/" + *DatasetID + "/" + *FileName

	method := "GET"

	client := &http.Client{}
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		fmt.Println(err)
		return fmt.Errorf("failed to make request, reason: %v", err)
	}

	req.Header.Add("Authorization", "Bearer "+config.AccessToken)
	req.Header.Add("client-public-key", base64publickey)

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

	var htsgetURLs htsgetResponse
	err = json.Unmarshal(body, &htsgetURLs)
	if err != nil {
		return fmt.Errorf("error unmarshaling response, reason: %v", err)
	}

	//fmt.Println(htsgetURLs.Htsget.Urls[0].URL)
	err = downloadFiles(htsgetURLs, config)
	if err != nil {
		return fmt.Errorf("error downloading the files, reason: %v", err)
	}
	return nil

}

func downloadFiles(htsgeURLs htsgetResponse, config *helpers.Config) (err error) {

	// Create the file in the current location
	var currentPath string
	currentPath, err = os.Getwd()
	if err != nil {
		return fmt.Errorf("failed to get current path, reason: %v", err)
	}

	//read public key from file
	publickey, err := os.ReadFile(currentPath + "/" + *PublicKeyFile)
	if err != nil {
		fmt.Println(err)
		return fmt.Errorf("failed to read public key, reason: %v", err)
	}
	base64publickey := base64.StdEncoding.EncodeToString(publickey)

	out, err := os.OpenFile(currentPath+"/data.c4gh", os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer out.Close()

	for index, _ := range htsgeURLs.Htsget.Urls {
		url := htsgeURLs.Htsget.Urls[index].URL

		// Case for base64 encoded data
		if strings.Contains(url, "data:;") {
			data, err := base64.StdEncoding.DecodeString(strings.SplitAfter(url, "data:;base64,")[1])
			if err != nil {
				fmt.Printf("error decoding the url response, %v", err)
				return err
			}
			_, err = io.Copy(out, bytes.NewBuffer(data))
			if err != nil {
				fmt.Printf("error copying the file, %v", err)
				return err
			}
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
		req.Header.Add("client-public-key", base64publickey)
		if htsgeURLs.Htsget.Urls[index].Headers.Range != "" {
			req.Header.Add("Range", htsgeURLs.Htsget.Urls[index].Headers.Range)
		}

		resp, err := client.Do(req)
		if err != nil {
			fmt.Println(err)
			return fmt.Errorf("failed to do the request, reason: %v", err)
		}
		defer resp.Body.Close()

		// Write the body to file
		_, err = io.Copy(out, resp.Body)
		if err != nil {
			fmt.Printf("error copying the file, %v", err)
			return err
		}

	}

	return nil

}
