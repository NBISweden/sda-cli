package version

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	rootcmd "github.com/NBISweden/sda-cli/cmd"
	"github.com/hashicorp/go-version"
	"github.com/spf13/cobra"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Show the version of sda-cli",
	Long:  "Show the version of the sda-cli tool",
	RunE: func(cmd *cobra.Command, args []string) error {
		err := printVersion(rootcmd.Version)
		if err != nil {
			return err
		}

		return nil
	},
}

func init() {
	rootcmd.AddCommand(versionCmd)
}

type ghResponse struct {
	Name      string `json:"name"`
	Published string `json:"published_at"`
	URL       string `json:"html_url"`
}

var url = "https://api.github.com/repos/NBISweden/sda-cli/releases/latest"
var timeout = 30 * time.Second

func printVersion(ver string) error {
	req, err := http.NewRequest(http.MethodGet, url, http.NoBody)
	if err != nil {
		fmt.Fprintln(os.Stderr, "failed to initiate request")
		fmt.Println("sda-cli version: ", ver)

		return nil
	}

	req.Header.Add("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Add("Accept", "application/vnd.github+json")

	client := &http.Client{Timeout: timeout}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to fetch releases, reason: %v\n", err.Error())
		fmt.Println("sda-cli version: ", ver)

		return nil
	}

	if resp.StatusCode >= 400 {
		fmt.Fprintf(os.Stderr, "failed to fetch releases, reason: %s\n", resp.Status)
		fmt.Println("sda-cli version: ", ver)

		return nil
	}
	defer resp.Body.Close() //nolint:errcheck

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
		fmt.Printf("Current sda-cli version: %v \n\n", ver)
		fmt.Printf("A newer version (%s) is available\n", ghVersion.Name)
		fmt.Printf("Released on: %s\n", pt.Format(time.DateTime))
		fmt.Printf("Download the latest version here: %s\n", ghVersion.URL)

		return nil
	}

	fmt.Println("sda-cli version: ", ver)

	return nil
}
