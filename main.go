package main

import (
	"flag"
	"fmt"
	"os"
	"reflect"

	createKey "github.com/NBISweden/sda-cli/create_key"
	"github.com/NBISweden/sda-cli/datasetsize"
	"github.com/NBISweden/sda-cli/decrypt"
	"github.com/NBISweden/sda-cli/download"
	"github.com/NBISweden/sda-cli/encrypt"
	zenGui "github.com/NBISweden/sda-cli/gui"
	"github.com/NBISweden/sda-cli/helpers"
	"github.com/NBISweden/sda-cli/htsget"
	"github.com/NBISweden/sda-cli/list"
	"github.com/NBISweden/sda-cli/login"
	sdaDownload "github.com/NBISweden/sda-cli/sda_download"
	"github.com/NBISweden/sda-cli/upload"
	"github.com/NBISweden/sda-cli/version"
	log "github.com/sirupsen/logrus"
)

var Version = "development"

var Usage = `USAGE: %s <command> [command-args]

This is a helper tool that can help with common tasks when interacting
with the Sensitive Data Archive (SDA).
`

// Map of the sub-commands, and their arguments and usage text strings
type commandInfo struct {
	args    *flag.FlagSet
	usage   string
	argHelp string
}

var Commands = map[string]commandInfo{
	"encrypt":      {encrypt.Args, encrypt.Usage, encrypt.ArgHelp},
	"createKey":    {createKey.Args, createKey.Usage, createKey.ArgHelp},
	"decrypt":      {decrypt.Args, decrypt.Usage, decrypt.ArgHelp},
	"download":     {download.Args, download.Usage, download.ArgHelp},
	"upload":       {upload.Args, upload.Usage, upload.ArgHelp},
	"datasetsize":  {datasetsize.Args, datasetsize.Usage, datasetsize.ArgHelp},
	"list":         {list.Args, list.Usage, list.ArgHelp},
	"htsget":       {htsget.Args, htsget.Usage, htsget.ArgHelp},
	"login":        {login.Args, login.Usage, login.ArgHelp},
	"sda-download": {sdaDownload.Args, sdaDownload.Usage, sdaDownload.ArgHelp},
	"version":      {version.Args, version.Usage, version.ArgHelp},
	"gui":          {},
}

// Main does argument parsing, then delegates to one of the sub modules
func main() {
	log.SetLevel(log.WarnLevel)
	command, args := ParseArgs()

	var err error

	switch command {
	case "encrypt":
		err = encrypt.Encrypt(args)
	case "createkey", "createKey", "create-key":
		err = createKey.CreateKey(args)
	case "decrypt":
		err = decrypt.Decrypt(args)
	case "download":
		err = download.Download(args)
	case "upload":
		err = upload.Upload(args)
	case "datasetsize":
		err = datasetsize.DatasetSize(args)
	case "list":
		err = list.List(args)
	case "htsget":
		err = htsget.Htsget(args)
	case "login":
		err = login.NewLogin(args)
	case "sda-download":
		err = sdaDownload.SdaDownload(args)
	case "version":
		err = version.Version(Version)
	case "gui":
		actions := reflect.ValueOf(Commands).MapKeys()
		err = zenGui.ZenityGui(actions)
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s", command)
		os.Exit(1)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

// Parses the command line arguments into a command, and keep the rest
// of the arguments for the subcommand.
func ParseArgs() (string, []string) {
	// Print usage if no arguments are provided.
	if len(os.Args) < 2 {
		_ = Help("help")
		os.Exit(1)
	}

	switch os.Args[1] {
	case "version", "-v", "-version", "--version":
		if len(os.Args) != 2 {
			_ = Help("version")
			os.Exit(0)
		}

		return "version", os.Args
	}

	// Extract the command from the 1st argument, then remove it
	// from list of arguments.
	command := os.Args[1]
	os.Args = append(os.Args[:1], os.Args[2:]...)

	// If the command is "help-like", we print the help text and
	// exit.  Let the Help function whether to exit with status zero
	// or one depending on whether the subcommand is valid or not.
	switch command {
	case "help", "-h", "-help", "--help":
		var subcommand string

		if len(os.Args) > 1 {
			subcommand = os.Args[1]
		} else {
			subcommand = "help"
		}
		// If the subcommand is not recognized, we exit with status 1
		err := Help(subcommand)
		if err != nil {
			os.Exit(1)
		}
		os.Exit(0)
	}

	// The "list" command can have no arguments since it can use the
	// config from login so we immediately return in that case.
	if command == "list" {
		return command, os.Args
	}

	// If no arguments are provided to the subcommand, it's not
	// going to be valid.  Print the subcommand help and exit with a
	// non-zero exit status.
	if len(os.Args) == 1 && command != "gui" {
		_ = Help(command)
		os.Exit(1)
	}

	return command, os.Args
}

// Prints the main usage string, and the global help or command help
// depending on the command argument.  Returns an error if the command
// is not recognized.
func Help(command string) error {
	info, isLegal := Commands[command]
	if !isLegal {
		if command != "help" {
			fmt.Fprintf(os.Stderr, "Unknown command: %s\n", command)
		}

		// print main help
		fmt.Fprintf(os.Stderr, Usage, os.Args[0])
		fmt.Fprintln(os.Stderr, "The tool can help with these actions:")
		for _, info := range Commands {
			subcommandUsage := helpers.FormatSubcommandUsage(info.usage)
			fmt.Fprint(os.Stderr, subcommandUsage)
		}
		fmt.Fprintf(os.Stderr,
			"use '%s help <command>' to get help with subcommand flags.\n",
			os.Args[0])

		if command == "help" {
			return nil
		}

		return fmt.Errorf("unknown command: %s", command)
	}

	// print subcommand help
	fmt.Fprintf(os.Stderr, info.usage+"\n", os.Args[0])
	fmt.Fprintln(os.Stderr, "Command line arguments:")
	info.args.PrintDefaults()
	fmt.Fprintln(os.Stderr, info.argHelp)

	return nil
}
