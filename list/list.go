//nolint:revive // package name conflict with stdlib is intentional
package list

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/NBISweden/sda-cli/apiclient"
	rootcmd "github.com/NBISweden/sda-cli/cmd"
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
var apiVersionFlag string

var listCmd = &cobra.Command{
	Use:   "list [flags] [args]",
	Short: "List files and datasets",
	Long: `Recursively list files and datasets in the user's folder in the Sensitive Data Archive (SDA).
	By default, it lists all files under the user's folder.
	Use a prefix as optional argument to list files under a specific path.

	On --api-version v2, the prefix is treated as a directory boundary: a
	trailing "/" is appended if missing, so "docs" matches "docs/foo" but
	not "docs-old". Use the S3 path on v1 for flat-prefix matching.

	Notice: If using '--datasets' or '--dataset' the '--url' flag is required to specify the SDA download server URL
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
	listCmd.Flags().StringVar(&dataset, "dataset", "", "List all files in the specified dataset, including dataset size")
	listCmd.Flags().BoolVar(&datasets, "datasets", false, "List all datasets available in the user's folder")
	listCmd.Flags().StringVar(&url, "url", "", "Specify the SDA download server URL")
	listCmd.Flags().StringVar(&apiVersionFlag, "api-version", "v1", "SDA download API version to use (v1 or v2)")
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
		err := datasetFiles(config.AccessToken, url, dataset, bytesFormat, prefix)
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

func datasetFiles(token string, url string, dataset string, bytesFormat bool, prefix string) error {
	client, err := apiclient.New(apiclient.Config{
		BaseURL: url,
		Token:   token,
		Version: rootcmd.Version,
	}, apiVersionFlag)
	if err != nil {
		return err
	}

	opts := apiclient.ListFilesOptions{}
	// v2 supports server-side pathPrefix filtering; push the prefix arg down
	// so the server returns only matching files. v1 has no such filter, so
	// the prefix is ignored there (use the S3 path for prefix-filtered listing
	// on v1).
	if apiVersionFlag == "v2" && prefix != "" {
		opts.PathPrefix = prefix
		if !strings.HasSuffix(opts.PathPrefix, "/") {
			opts.PathPrefix += "/"
		}
	}

	files, err := client.ListFiles(context.Background(), dataset, opts)
	if err != nil {
		// URL-validation errors are returned unwrapped so TestListDatasetNoUrl
		// still sees the bare "invalid base URL" string; transport / parse /
		// HTTP errors get the legacy "failed to get files, reason: ..."
		// prefix that callers of the previous download.GetFilesInfo shim
		// expected before apiclient was introduced.
		if err.Error() == "invalid base URL" {
			return err
		}

		return fmt.Errorf("failed to get files, reason: %v", err)
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
	client, err := apiclient.New(apiclient.Config{
		BaseURL: url,
		Token:   token,
		Version: rootcmd.Version,
	}, apiVersionFlag)
	if err != nil {
		return err
	}

	ctx := context.Background()
	datasets, err := client.ListDatasets(ctx)
	if err != nil {
		// Same contract as datasetFiles above: bare "invalid base URL"
		// preserved for TestListDatasetsNoUrl; every other failure gets the
		// legacy "failed to get datasets, reason: ..." prefix that the
		// pre-apiclient download.GetDatasets shim used to emit.
		if err.Error() == "invalid base URL" {
			return err
		}

		return fmt.Errorf("failed to get datasets, reason: %v", err)
	}

	fileIDWidth := 40 // fileIdwith=40 ensures header matches rest of the table
	fmt.Printf("%-*s \t %s \t %s\n", fileIDWidth, "DatasetID", "Files", "Size")

	// v2 has a /datasets/{id} metadata endpoint that returns count+size
	// directly; use it to avoid the N+1 file scan. v1 has no such endpoint,
	// so we fall back to ListFiles per dataset (unavoidable for v1).
	for _, dataset := range datasets {
		if apiVersionFlag == "v2" {
			info, err := client.DatasetInfo(ctx, dataset)
			if err != nil {
				// Per-dataset enrichment is still "get datasets" from the
				// CLI user's perspective; keep the legacy wrap prefix so v2
				// matches the v1 contract for failures.
				return fmt.Errorf("failed to get datasets, reason: %v", err)
			}
			fmt.Printf("%s \t %d \t %s\n", dataset, info.FileCount, formatFileSizeOutput(int(info.Size), bytesFormat))

			continue
		}

		files, err := client.ListFiles(ctx, dataset, apiclient.ListFilesOptions{})
		if err != nil {
			// URL was already validated by ListDatasets above, so any failure
			// here is transport/parse/HTTP and takes the legacy wrap prefix.
			return fmt.Errorf("failed to get files, reason: %v", err)
		}
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
