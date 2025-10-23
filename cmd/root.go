package cmd

import (
	"github.com/spf13/cobra"
)

var Version = "0-development"

var rootCmd = &cobra.Command{
	Use:   "sda-cli",
	Short: "CLI tool used to interact with SDA",
	Long: `Command line tool used to interact with the Sensitive Data Archive (SDA)
	For more infomration, see the README at https://github.com/NBISweden/sda-cli/blob/main/README.md`,
}

func Execute() error {
	err := rootCmd.Execute()
	if err != nil {
		return err
	}

	return nil
}

func init() {
	rootCmd.PersistentFlags().StringP("config", "c", "s3cmd.conf", "The configuration file for s3cmd")
}

func AddCommand(command *cobra.Command) {
	rootCmd.AddCommand(command)
}
