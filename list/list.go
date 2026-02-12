//nolint:revive // package name conflict with stdlib is intentional
package list

import (
	"fmt"
	"strconv"
	"strings"

	rootcmd "github.com/NBISweden/sda-cli/cmd"
	"github.com/NBISweden/sda-cli/download"
	"github.com/NBISweden/sda-cli/helpers"
	"github.com/dustin/go-humanize"
	"github.com/inhies/go-bytesize"
	"github.com/spf13/cobra"
)

var dataset string
var datasets bool
var url string
var prefix string
var bytesFormat bool

var listCmd = &cobra.Command{
	Use:   "list [flags] [args]",
	Short: "List files and datasets",
	Long: `Recursively list files and datasets in the user's folder in the Sensitive Data Archive (SDA). 
	By default, it lists all files under the user's folder. 
	Use a prefix as optional argument to list files under a specific path.

	Notice: If using '--datasets' or '--dataset' the '-url' flag is required to specify the SDA download server URL
`,
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) > 1 {
			return fmt.Errorf("can only accept 1 prefix argument, got %d : %s", len(args), args)
		}
		if len(args) == 0 {
			prefix = ""

			return nil
		}
		prefix = args[0]

		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		configPath := cmd.Root().Flag("config").Value.String()
		err := list(configPath, prefix)
		if err != nil {
			return err
		}

		return nil
	},
}

func init() {
	rootcmd.AddCommand(listCmd)
	listCmd.Flags().BoolVar(&bytesFormat, "bytes", false, "Display file sizes in bytes instead of human-readable format")
	listCmd.Flags().StringVar(&dataset, "dataset", "", "List all files in the sepcified dataset, including dataset size")
	listCmd.Flags().BoolVar(&datasets, "datasets", false, "List all datasets available in the user's folder")
	listCmd.Flags().StringVar(&url, "url", "", "Specify the SDA download server URL")
}

func list(configPath string, prefix string) error {
	config, err := helpers.GetAuth(configPath)
	if err != nil {
		return fmt.Errorf("failed to load config file, reason: %v", err)
	}

	err = helpers.CheckTokenExpiration(config.AccessToken)
	if err != nil {
		return err
	}

	helpers.PrintHostBase(config.HostBase)

	if datasets {
		err := Datasets(url, config.AccessToken)
		if err != nil {
			return err
		}

		return nil
	}

	if dataset != "" {
		err := datasetFiles(config.AccessToken, url, dataset, bytesFormat)
		if err != nil {
			return err
		}

		return nil
	}

	result, err := helpers.ListFiles(*config, prefix)
	if err != nil {
		return err
	}

	for i := range result {
		file := *result[i].Key
		fmt.Printf("%s \t %s \n", bytesize.New(float64((*result[i].Size))), file[strings.Index(file, "/")+1:])
	}

	return nil
}

func datasetFiles(token string, url string, dataset string, bytesFormat bool) error {
	files, err := download.GetFilesInfo(url, dataset, "", token, rootcmd.Version)
	if err != nil {
		return err
	}

	fileIDWidth, sizeWidth := 20, 10 // Set minimum column widths, so that header matches the rest of the table
	fmt.Printf("%-*s \t %-*s \t %s\n", fileIDWidth, "FileID", sizeWidth, "Size", "Path")
	datasetSize := 0

	for _, file := range files {
		datasetSize += file.DecryptedFileSize
		fmt.Printf("%s \t %s \t %s\n", file.FileID, formatFileSizeOutput(file.DecryptedFileSize, bytesFormat), file.FilePath)
	}
	fmt.Printf("Dataset size: %s\n", formatFileSizeOutput(datasetSize, bytesFormat))

	return nil
}

func formatFileSizeOutput(size int, bytesFormat bool) string {
	if !bytesFormat {
		return humanize.Bytes(uint64(size))
	}

	return strconv.Itoa(size)
}

func Datasets(url string, token string) error {
	datasets, err := download.GetDatasets(url, token, rootcmd.Version)
	if err != nil {
		return err
	}

	for _, dataset := range datasets {
		files, err := download.GetFilesInfo(url, dataset, "", token, rootcmd.Version)
		if err != nil {
			return err
		}
		fileIDWidth := 40 // fileIdwith=40 ensures header matches rest of the table
		fmt.Printf("%-*s \t %s \t %s\n", fileIDWidth, "DatasetID", "Files", "Size")
		datasetSize := 0
		noOfFiles := 0
		for _, file := range files {
			datasetSize += file.DecryptedFileSize
			noOfFiles++
		}
		fmt.Printf("%s \t %d \t %s\n", dataset, noOfFiles, formatFileSizeOutput(datasetSize, bytesFormat))
	}

	return nil
}
