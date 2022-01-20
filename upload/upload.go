package upload

import (
	"flag"
	"os"

	log "github.com/sirupsen/logrus"
)

// Help text and command line flags.

var Usage = `
USAGE: %s upload -config <s3config-file> [file(s)]

Upload: Uploads files to the Secure Data Archive (SDA). All files to upload are
        required to be encrypted and have the .c4gh file extension.
`
var ArgHelp = `
  [file(s)]
        all flagless arguments will be used as filenames to upload.`

var Args = flag.NewFlagSet("upload", flag.ExitOnError)

var config = Args.String("config", "", "S3 config file to use for uploading.")

// Main upload function
func Upload(args []string) {
	Args.Parse(os.Args[1:])

	// Args() returns the non-flag arguments, which we assume are filenames.
	files := Args.Args()

	// Check that we have a private key to decrypt with
	if *config == "" {
		log.Fatal("An s3config is required to upload data")
	}
	log.Infof("Uploading %s with config %s", files, *config)
}
