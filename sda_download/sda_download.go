package sdadownload

import (
	"flag"
	"fmt"
	"io"
	"net/http"

	"github.com/NBISweden/sda-cli/helpers"
)

// Help text and command line flags.

// Usage text that will be displayed as command line help text when using the
// `help download` command
var Usage = `
USAGE: %s sda-download -config <s3config-file> (-outdir <dir>) [uri]

sda-download:
	Downloads files from the Sensitive Data Archive (SDA) by using APIs. The user
	must have been granted access to the datasets (visas) that are to be downloaded.
	The files will be downloaded in the current directory, if outdir is not defined
`

// ArgHelp is the suffix text that will be displayed after the argument list in
// the module help
var ArgHelp = `
    [uri]
        All flagless arguments will be used as sda-download uri.`

// Args is a flagset that needs to be exported so that it can be written to the
// main program help
var Args = flag.NewFlagSet("sda-download", flag.ExitOnError)

var configPath = Args.String("config", "",
	"S3 config file to use for downloading.")

var outDir = Args.String("outdir", "",
	"Directory for downloaded files.")

// SdaDownload function downloads files from the SDA by using the
// download's service APIs
func SdaDownload(args []string) error {
	// Call ParseArgs to take care of all the flag parsing
	err := helpers.ParseArgs(args, Args)
	if err != nil {
		return fmt.Errorf("failed parsing arguments, reason: %v", err)
	}

	uri := ""
	if len(Args.Args()) > 1 {
		return fmt.Errorf("failed to parse uri, only one is allowed")
	} else if len(Args.Args()) == 0 {
		return fmt.Errorf("failed to find uri, no argument parsed")
	} else if len(Args.Args()) == 1 {
		uri = Args.Args()[0]
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

	// Get the response
	err = getResponse(uri, config.AccessToken)
	if err != nil {
		return err
	}

	return nil
}

// getResponse gets the response from the SDA download service
func getResponse(url, token string) error {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request, reason: %v", err)
	}

	// Add headers
	req.Header.Add("Authorization", "Bearer "+token)
	req.Header.Add("Content-Type", "application/json")

	// Send the request
	client := &http.Client{}
	res, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to get response, reason: %v", err)
	}

	// Read the response body
	resBody, err := io.ReadAll(res.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body, reason: %v", err)
	}

	fmt.Println(string(resBody))

	defer res.Body.Close()

	return nil
}
