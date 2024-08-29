package list

import (
	"flag"
	"fmt"
	"strconv"

	"strings"

	"github.com/NBISweden/sda-cli/download"
	"github.com/NBISweden/sda-cli/helpers"
	"github.com/dustin/go-humanize"
	"github.com/inhies/go-bytesize"
)

// Help text and command line flags.

// Usage text that will be displayed as command line help text when using the
// `help list` command
var Usage = `
USAGE: %s list [-config <s3config-file>] [prefix] (-url <uri> --datasets) (-url <uri> --dataset <dataset-id>) [-bytes]

list:
    Lists recursively all files under the user's folder in the Sensitive
    Data Archive (SDA).  If the [prefix] parameter is used, only the
    files under the specified path will be returned. If no config is
	specified, the tool will look for a previous session. The --datasets
	flag will list all datasets in the user's folder, given the url of
	the	htsgetserver. The --dataset flag will list all files in the
	specified dataset and the dataset size.
`

// ArgHelp is the suffix text that will be displayed after the argument list in
// the module help
var ArgHelp = `
    [prefix]
        The location/folder of the s3 to list contents.`

// Args is a flagset that needs to be exported so that it can be written to the
// main program help
var Args = flag.NewFlagSet("list", flag.ExitOnError)

var configPath = Args.String("config", "",
	"S3 config file to use for listing.")

var URL = Args.String("url", "", "The url of the sda-download server")

var datasets = Args.Bool("datasets", false, "List all datasets in the user's folder.")

var bytesFormat = Args.Bool("bytes", false, "Print file sizes in bytes (not human-readable format).")

var dataset = Args.String("dataset", "", "List all files in the specified dataset.")

// List function lists the contents of an s3
func List(args []string) error {
	// Call ParseArgs to take care of all the flag parsing
	err := helpers.ParseArgs(args, Args)
	if err != nil {
		return fmt.Errorf("failed parsing arguments, reason: %v", err)
	}

	prefix := ""
	if len(Args.Args()) == 1 {
		prefix = Args.Args()[0]
	}

	// // Get the configuration file or the .sda-cli-session
	config, err := helpers.GetAuth(*configPath)
	if err != nil {
		return fmt.Errorf("failed to load config file, reason: %v", err)
	}

	err = helpers.CheckTokenExpiration(config.AccessToken)
	if err != nil {
		return err
	}
	// case datasets
	if *datasets {
		err := Datasets(config.AccessToken)
		if err != nil {
			return err
		}

		return nil
	}

	// case dataset
	if *dataset != "" {
		err := DatasetFiles(config.AccessToken)
		if err != nil {
			return err
		}

		return nil
	}

	result, err := helpers.ListFiles(*config, prefix)
	if err != nil {
		return err
	}

	for i := range result.Contents {
		file := *result.Contents[i].Key
		fmt.Printf("%s \t %s \n", bytesize.New(float64((*result.Contents[i].Size))), file[strings.Index(file, "/")+1:])
	}

	return nil
}

func DatasetFiles(token string) error {
	files, err := download.GetFilesInfo(*URL, *dataset, "", token)
	if err != nil {
		return err
	}
	// Set rather long minimum column widths, so that header matches the rest of the table
	fileIDWidth, sizeWidth := 20, 10
	fmt.Printf("%-*s \t %-*s \t %s\n", fileIDWidth, "FileID", sizeWidth, "Size", "Path")
	datasetSize := 0
	// Loop through the files and list them
	for _, file := range files {
		datasetSize += file.DecryptedFileSize
		fmt.Printf("%s \t %s \t %s\n", file.FileID, formatedBytes(file.DecryptedFileSize), file.FilePath)
	}
	fmt.Printf("Dataset size: %s\n", formatedBytes(datasetSize))

	return nil
}

func formatedBytes(size int) string {
	if !*bytesFormat {
		return humanize.Bytes(uint64(size))
	}

	return strconv.Itoa(size)
}

func Datasets(token string) error {
	datasets, err := download.GetDatasets(*URL, token)
	if err != nil {
		return err
	}

	// Loop through the datasets and list them
	for _, dataset := range datasets {
		files, err := download.GetFilesInfo(*URL, dataset, "", token)
		if err != nil {
			return err
		}
		// Set rather long minimum column widths, so that header matches the rest of the table
		fileIDWidth := 40
		fmt.Printf("%-*s \t %s \t %s\n", fileIDWidth, "DatasetID", "Files", "Size")
		datasetSize := 0
		noOfFiles := 0
		// Loop through the files and get their sizes
		for _, file := range files {
			datasetSize += file.DecryptedFileSize
			noOfFiles++
		}
		fmt.Printf("%s \t %d \t %s\n", dataset, noOfFiles, formatedBytes(datasetSize))
	}

	return nil
}
