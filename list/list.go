package list

import (
	"errors"
	"flag"
	"fmt"

	"strings"

	"github.com/NBISweden/sda-cli/helpers"
	"github.com/inhies/go-bytesize"
)

// Help text and command line flags.

// Usage text that will be displayed as command line help text when using the
// `help list` command
var Usage = `
USAGE: %s list [-config <s3config-file>] [prefix]

list:
    Lists recursively all files under the user's folder in the Sensitive
    Data Archive (SDA).  If the [prefix] parameter is used, only the
    files under the specified path will be returned. If no config is
	specified, the tool will look for a previous session.
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

// List function lists the contents of an s3
func List(args []string) error {
	// Call ParseArgs to take care of all the flag parsing
	err := helpers.ParseArgs(args, Args)
	if err != nil {
		return fmt.Errorf("failed parsing arguments, reason: %v", err)
	}

	prefix := ""
	if len(Args.Args()) > 1 {
		return errors.New("failed to parse prefix, only one is allowed")
	} else if len(Args.Args()) == 1 {
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
