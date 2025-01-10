package main

import (
	"flag"
	"fmt"
	"os"

	createKey "github.com/NBISweden/sda-cli/create_key"
	"github.com/NBISweden/sda-cli/decrypt"
	"github.com/NBISweden/sda-cli/download"
	"github.com/NBISweden/sda-cli/encrypt"
	"github.com/NBISweden/sda-cli/htsget"
	"github.com/NBISweden/sda-cli/list"
	"github.com/NBISweden/sda-cli/login"
	"github.com/NBISweden/sda-cli/upload"
	"github.com/NBISweden/sda-cli/version"
	log "github.com/sirupsen/logrus"
)

var Version = "0-development"
const ExecName = "sda-cli"

var Usage = fmt.Sprintf(`
Usage: %s [-config CONFIGFILE] <command> [OPTIONS]

A tool for common tasks with the Sensitive Data Archive (SDA)

Commands:
  createKey   Creates a Crypt4GH key pair
  decrypt     Decrypt files
  download    Download files from SDA
  encrypt     Encrypt files
  htsget      Get files using htsget
  list        List files in the SDA
  login       Login to the SDA
  upload      Upload files to the SDA

Global options:
  -config CONFIGFILE  Path to the configuration file
  -h, -help           Show this help message
  -v, -version        Show the version of the tool

Additional commands:
  version          Show the version of the tool
  help             Show this help message

Run '%s help <command>' for more information on a command.
`, ExecName, ExecName)

// Map of the sub-commands, and their arguments and usage text strings
type commandInfo struct {
	args    *flag.FlagSet
	usage   string
	argHelp string
}

var Commands = map[string]commandInfo{
	"encrypt":   {encrypt.Args, encrypt.Usage, encrypt.ArgHelp},
	"createKey": {createKey.Args, createKey.Usage, createKey.ArgHelp},
	"decrypt":   {decrypt.Args, decrypt.Usage, decrypt.ArgHelp},
	"upload":    {upload.Args, upload.Usage, upload.ArgHelp},
	"list":      {list.Args, list.Usage, list.ArgHelp},
	"htsget":    {htsget.Args, htsget.Usage, htsget.ArgHelp},
	"login":     {login.Args, login.Usage, login.ArgHelp},
	"download":  {download.Args, download.Usage, download.ArgHelp},
	"version":   {version.Args, version.Usage, version.ArgHelp},
}

// Main does argument parsing, then delegates to one of the sub modules
func main() {

	log.SetLevel(log.WarnLevel)
	command, args, configPath := ParseArgs()

	var err error

	switch command {
	case "encrypt":
		err = encrypt.Encrypt(args)
	case "createkey", "createKey", "create-key":
		err = createKey.CreateKey(args)
	case "decrypt":
		err = decrypt.Decrypt(args)
	case "upload":
		err = upload.Upload(args, configPath)
	case "list":
		err = list.List(args, configPath)
	case "htsget":
		err = htsget.Htsget(args, configPath)
	case "login":
		err = login.NewLogin(args)
	case "download":
		err = download.Download(args, configPath)
	case "version":
		err = version.Version(Version)
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s", command)
		os.Exit(1)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	os.Exit(0)
}

// Parse the command line arguments into a command, and keep the rest
// of the arguments for the subcommand.
func ParseArgs() (string, []string, string) {
	var configPath string
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

		return "version", os.Args, ""
	case "--config", "-config":
		if len(os.Args) < 3 {
			fmt.Fprintf(os.Stderr, "Error: --config requires an argument\n")
			os.Exit(1)
		}
		configPath = os.Args[2]
		os.Args = append(os.Args[:1], os.Args[3:]...)
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
		return command, os.Args, configPath
	}

	// If no arguments are provided to the subcommand, it's not
	// going to be valid.  Print the subcommand help and exit with a
	// non-zero exit status.
	if len(os.Args) == 1 {
		_ = Help(command)
		os.Exit(1)
	}

	return command, os.Args, configPath
}

// Print the main usage string, and the global help or command help
// depending on the command argument.  Returns an error if the command
// is not recognized.
func Help(command string) error {
	info, isLegal := Commands[command]
	if !isLegal {
		if command != "help" {
			fmt.Fprintf(os.Stderr, "Unknown command: %s\n", command)
		}

		// print main help
		fmt.Println(Usage)

		if command == "help" {
			return nil
		}

		return fmt.Errorf("unknown command: %s", command)
	}

	// Print subcommand help
	fmt.Printf(info.usage+"\n", ExecName)
	// fmt.Println("Command line arguments:")
	// info.args.PrintDefaults()
	// fmt.Println(info.argHelp)

	return nil
}
