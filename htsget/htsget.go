package htsget

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/NBISweden/sda-cli/cmd"
	"github.com/NBISweden/sda-cli/helpers"
	"github.com/spf13/cobra"
)

var datasetID string
var fileName string
var referenceName string
var htsgetHost string
var publicKeyFile string
var output string
var forceOverwrite bool

var htsgetCmd = &cobra.Command{
	Use:   "htsget [flags]",
	Short: "Download files from SDA",
	Long:  "Download files from the Sensitive Data Archive (SDA) using the htsget server",
	RunE: func(cmd *cobra.Command, args []string) error {
		configPath := cmd.Root().Flag("config").Value.String()
		err := Htsget(args, configPath)
		if err != nil {
			return err
		}

		return nil
	},
}

func init() {
	cmd.AddCommand(htsgetCmd)
	htsgetCmd.Flags().StringVar(&datasetID, "dataset", "", "The dataset id of the file to download")
	htsgetCmd.Flags().StringVar(&fileName, "filename", "", "The name of the file to download")
	htsgetCmd.Flags().StringVar(&referenceName, "reference", "", "The reference number of the file to download")
	htsgetCmd.Flags().StringVar(&htsgetHost, "host", "", "The htsget host to download from")
	htsgetCmd.Flags().StringVar(&publicKeyFile, "pubkey", "", "Path to the public key file to use for download")
	htsgetCmd.Flags().StringVar(&output, "output", "", "Name to output the file as after download")
	htsgetCmd.Flags().BoolVar(&forceOverwrite, "force-overwrite", false, "Force overwriting existing files")
}

type HtsgetHeaders struct {
	Range          string `json:"Range"`
	UserAgent      string `json:"user-agent"`
	Host           string `json:"host"`
	AcceptEncoding string `json:"accept-encoding"`
	Authorization  string `json:"authorization"`
}

type HtsgetURL struct {
	URL     string        `json:"url"`
	Headers HtsgetHeaders `json:"headers"`
}

type HtsgetInfo struct {
	Format string      `json:"format"`
	Urls   []HtsgetURL `json:"urls"`
}

type HtsgetResponse struct {
	Htsget HtsgetInfo `json:"htsget"`
}

func Htsget(_ []string, configPath string) error {
	if datasetID == "" || fileName == "" || htsgetHost == "" || publicKeyFile == "" {
		return errors.New("missing required arguments, dataset, filename, host and key are required")
	}

	config, err := helpers.GetAuth(configPath)
	if err != nil {
		return err
	}

	publickey, err := os.ReadFile(publicKeyFile)
	if err != nil {
		return fmt.Errorf("failed to read public key, reason: %v", err)
	}
	base64publickey := base64.StdEncoding.EncodeToString(publickey)

	// TODO: Add cases for different type of files
	// i.e. bam files require the /reads/, replace for vcf
	url := htsgetHost + "/reads/" + datasetID + "/" + fileName + "?encryptionScheme=C4GH"
	if referenceName != "" {
		url += "&referenceName=" + referenceName
	}
	method := "GET"
	client := &http.Client{}
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		return fmt.Errorf("failed to make request, reason: %v", err)
	}

	req.Header.Add("Authorization", "Bearer "+config.AccessToken)
	req.Header.Add("Htsget-Context-Public-Key", base64publickey)

	res, err := client.Do(req) // #nosec G704

	if err != nil {
		return fmt.Errorf("failed to do the request, reason: %v", err)
	}
	if res.StatusCode != 200 {
		return fmt.Errorf("failed to get the file, status code: %v", res.StatusCode)
	}
	defer res.Body.Close() //nolint:errcheck

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return fmt.Errorf("failed to read response, reason: %v", err)
	}

	htsgetURLs := HtsgetResponse{}
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

func downloadFiles(htsgeURLs HtsgetResponse, config *helpers.Config) (err error) {
	// Create the directory for the file
	var filePath string
	if strings.Contains(fileName, string(os.PathSeparator)) {
		filePath = filepath.Dir(fileName)
		err = os.MkdirAll(filePath, 0750)
		if err != nil {
			return fmt.Errorf("failed to create file path, reason: %v", err)
		}
	}
	filenameToUse := fileName
	// If output is specified, use it directly without checking for encrypted data
	if output != "" {
		filenameToUse = output
	} else {
		// Check if we have encrypted data to use the right file extension
		for index := range htsgeURLs.Htsget.Urls {
			if strings.Contains(htsgeURLs.Htsget.Urls[index].URL, "base64") {
				filenameToUse = fileName + ".c4gh"

				break
			}
		}
	}

	if helpers.FileExists(filenameToUse) && !forceOverwrite {
		return errors.New("local file already exists, use -force-overwrite to overwrite")
	}
	out, err := os.OpenFile(filenameToUse, os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer out.Close() //nolint:errcheck

	// read public key from file
	publickey, err := os.ReadFile(publicKeyFile)
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
		req.Header.Add("Client-Public-Key", base64publickey)
		if htsgeURLs.Htsget.Urls[index].Headers.Range != "" {
			req.Header.Add("Range", htsgeURLs.Htsget.Urls[index].Headers.Range)
		}

		res, err := client.Do(req) // #nosec G704
		if err != nil {
			deleteFile(out)

			return fmt.Errorf("failed to do the request, reason: %v", err)
		}
		if res.StatusCode != 200 {
			deleteFile(out)

			return fmt.Errorf("failed to get the file, status code: %v", res)
		}
		defer res.Body.Close() //revive:disable:defer

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
	_ = os.Remove(name) // #nosec G703
}
