package version

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/hashicorp/go-version"
)

// Help text and command line flags.

// Usage text that will be displayed as command line help text when using the
// `help version` command
var Usage = `
USAGE: %s version

version:
    Returns the version of the sda-cli tool.
`

// ArgHelp is the suffix text that will be displayed after the argument list in
// the module help
var ArgHelp = `
    version does not take any arguments`

// Args is a flagset that needs to be exported so that it can be written to the
// main program help
var Args = flag.NewFlagSet("version", flag.ExitOnError)

type ghResponse struct {
	Name      string `json:"name"`
	Published string `json:"published_at"`
	URL       string `json:"html_url"`
}

// this is just so we can mock bad internet connection
var url = "https://api.github.com/repos/NBISweden/sda-cli/releases/latest"
var timeout = 30 * time.Second

// Returns the version of the sda-cli tool.
func Version(ver string) error {
	if len(Args.Args()) > 0 {
		return errors.New("version does not take any arguments")
	}

	req, err := http.NewRequest(http.MethodGet, url, http.NoBody)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to initiate request")
		fmt.Println("sda-cli version: ", ver)

		return nil
	}
	req.Header.Add("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Add("Accept", "application/vnd.github+json")

	client := &http.Client{Timeout: timeout}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to fetch releases, reason: %s\n", err.Error())
		fmt.Println("sda-cli version: ", ver)

		return nil
	}
	if resp.StatusCode >= 400 {
		fmt.Fprintf(os.Stderr, "failed to fetch releases, reason: %s\n", resp.Status)
		fmt.Println("sda-cli version: ", ver)

		return nil
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Fprintln(os.Stderr, "failed to read response")
		fmt.Println("sda-cli version: ", ver)

		return nil
	}

	ghVersion := ghResponse{}
	if err := json.Unmarshal(body, &ghVersion); err != nil {
		fmt.Fprintln(os.Stderr, "failed to unmarshal response")
		fmt.Println("sda-cli version: ", ver)

		return nil
	}

	appVer, err := version.NewVersion(ver)
	if err != nil {
		fmt.Fprintln(os.Stderr, "failed to parse app version")
		fmt.Println("sda-cli version: ", ver)

		return nil
	}
	ghVer, err := version.NewVersion(ghVersion.Name)
	if err != nil {
		fmt.Fprintln(os.Stderr, "failed to parse release version")
		fmt.Println("sda-cli version: ", ver)

		return nil
	}

	if appVer.LessThan(ghVer) {
		pt, _ := time.Parse(time.RFC3339, ghVersion.Published)
		fmt.Printf("Newer version of sda-cli is available, %s\n", ghVersion.Name)
		fmt.Printf("Published: %s\n", pt.Format(time.DateTime))
		fmt.Printf("Download it from here: %s\n", ghVersion.URL)

		return nil
	}

	fmt.Println("sda-cli version: ", ver)

	return nil
}
