package version

import (
	"errors"
	"flag"
	"fmt"
)

// Help text and command line flags.

// Usage text that will be displayed as command line help text when using the
// `help version` command
var Usage = `
USAGE: %s version

version:
    Returns the version of the sda-cli tool.
`

// ArgHelp is the suffix text that will be displayed after the argument list in
// the module help
var ArgHelp = `
    version does not take any arguments`

// Args is a flagset that needs to be exported so that it can be written to the
// main program help
var Args = flag.NewFlagSet("version", flag.ExitOnError)

// Returns the version of the sda-cli tool.
func Version(ver string) error {
	if len(Args.Args()) > 0 {
		return errors.New("version does not take any arguments")
	}
	fmt.Println("sda-cli version: ", ver)

	return nil
}
