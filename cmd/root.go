package cmd

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
)

var Version = "0-development"

var rootCmd = &cobra.Command{
	Use:           "sda-cli",
	Short:         "CLI tool used to interact with SDA",
	Long:          `Command line tool used to interact with the Sensitive Data Archive (SDA)`,
	SilenceUsage:  true,
}

func Execute() error {
	err := rootCmd.Execute()
	if err != nil {
		return err
	}

	return nil
}

func init() {
	readmeURL := "https://github.com/NBISweden/sda-cli/blob/main/README.md"
	if !strings.Contains(Version, "development") {
		readmeURL = fmt.Sprintf("https://github.com/NBISweden/sda-cli/blob/%s/README.md", Version)
	}
	rootCmd.PersistentFlags().StringP("config", "c", "s3cmd.conf", "The configuration file for s3cmd")
	rootCmd.Long += fmt.Sprintf("\nFor more information, see the README at: %s", readmeURL)
}

func AddCommand(command *cobra.Command) {
	rootCmd.AddCommand(command)
}
