package download

import (
	"flag"
	"os"

	log "github.com/sirupsen/logrus"
)

// Help text and command line flags.

var Usage = `
USAGE: %s download [url(s)]

Download: Downloads files from the Sensitive Data Archive (SDA). If a directory is
          provided (ending with "/"), then the tool will attempt to first
          download the urls_list.txt file, and then download all files in this
          list. If file urls are given, they will be downloaded as-is.
`
var ArgHelp = `
  [urls]
        all flagless arguments will be used as download urls.`

var Args = flag.NewFlagSet("download", flag.ExitOnError)

// Main download function
func Download(args []string) {
	// Parse flags. There are no flags at the moment, but in case some are added
	// we check for them.
	err := Args.Parse(os.Args[1:])
	if err != nil {
		log.Fatalf("Argument parsing failed, reason: %v", err)
	}

	// Args() returns the non-flag arguments, which we assume are filenames.
	urls := Args.Args()

	log.Infof("Downloading urls %s", urls)
}
