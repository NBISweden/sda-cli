package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/NBISweden/sda-cli/decrypt"
	"github.com/NBISweden/sda-cli/download"
	"github.com/NBISweden/sda-cli/encrypt"
	"github.com/NBISweden/sda-cli/upload"
	log "github.com/sirupsen/logrus"
)

var Usage = `USAGE: %s <command> [command-args]

This is a helper tool that can help with common tasks when interacting with the
Sensitive Data Archive (SDA).
`

//  Map of the sub-commands, and their arguments and usage text strings
type commandInfo struct {
	args    *flag.FlagSet
	usage   string
	argHelp string
}

var Commands = map[string]commandInfo{
	"encrypt":  {encrypt.Args, encrypt.Usage, encrypt.ArgHelp},
	"decrypt":  {decrypt.Args, decrypt.Usage, decrypt.ArgHelp},
	"download": {download.Args, download.Usage, download.ArgHelp},
	"upload":   {upload.Args, upload.Usage, upload.ArgHelp},
}

// Main does argument parsing, then delegates to one of the sub modules
func main() {

	command, args := ParseArgs()

	var err error

	switch command {
	case "encrypt":
		err = encrypt.Encrypt(args)
	case "decrypt":
		decrypt.Decrypt(args)
	case "download":
		err = download.Download(args)
	case "upload":
		err = upload.Upload(args)
	default:
		log.Fatal("Unknown command:", command)
	}
	if err != nil {
		log.Fatal(err)
	}
}

// Parses the command line arguments into a command, and keep the rest of the
// arguments for the subcommand
func ParseArgs() (string, []string) {

	// Print usage if no arguments are provided
	if len(os.Args) < 2 {
		Help("help")
	}

	// Extract `command` from arg 1, then remove it from the flag list.
	command := os.Args[1]
	os.Args = append(os.Args[:1], os.Args[2:]...)

	// If `command` is help-like, we print the help text and exit
	switch command {
	case "-h", "help", "-help", "--help":
		var subcommand string
		if len(os.Args) > 1 {
			subcommand = os.Args[1]
		} else {
			subcommand = "help"
		}
		Help(subcommand)
	}

	return command, os.Args
}

// Prints the main usage string, and the global help or command help depending
// on the `command` arg.
func Help(command string) {

	info, isLegal := Commands[command]
	if isLegal {
		// print subcommand help
		fmt.Fprintf(os.Stderr, info.usage, os.Args[0])
		fmt.Fprintln(os.Stderr, "Command line arguments:")
		info.args.PrintDefaults()
		fmt.Fprintln(os.Stderr, info.argHelp)
	} else {
		if command != "help" {
			fmt.Fprintf(os.Stderr, "Unknown command: %s\n", command)
		}
		// print main help
		fmt.Fprintf(os.Stderr, Usage, os.Args[0])
		fmt.Fprintln(os.Stderr, "The tool can help with these actions:")
		for subcommand, info := range Commands {
			// Break up the usage command to be more readable. This depends on
			// all of the usage strings being correctly formatted for this tool.
			lines := strings.Split(fmt.Sprintf(info.usage, os.Args[0]), "\n")
			if len(lines) < 2 {
				// if we don't have enough data, just print the usage string
				fmt.Fprintf(os.Stderr, "%s\n", fmt.Sprintf(info.usage, os.Args[0]))
				continue
			}
			usage := lines[1]
			format := "%s\n%" + fmt.Sprintf("%v", len(subcommand)+2) + "s%s\n\n"

			fmt.Fprintf(os.Stderr, format, strings.Join(lines[2:], "\n"), " ", usage)
		}
		fmt.Fprintf(os.Stderr,
			"Use '%s help <command>' to get help with subcommand flags.\n",
			os.Args[0])
	}

	os.Exit(1)
}
