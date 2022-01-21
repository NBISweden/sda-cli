package decrypt

import (
	"flag"
	"os"

	log "github.com/sirupsen/logrus"
)

// Help text and command line flags.

var Usage = `
USAGE: %s decrypt -key <private-key-file> [file(s)]

Decrypt: Encrypts files from the Sensitive Data Archive (SDA) with the provided
         private key.
`
var ArgHelp = `
  [file(s)]
        all flagless arguments will be used as filenames for decryption.`

var Args = flag.NewFlagSet("decrypt", flag.ExitOnError)

var privateKey = Args.String("key", "",
	"Private key to use for decrypting files.")

// Main decryption function
func Decrypt(args []string) {
	Args.Parse(os.Args[1:])

	// Args() returns the non-flag arguments, which we assume are filenames.
	files := Args.Args()

	// Check that we have a private key to decrypt with
	if *privateKey == "" {
		log.Fatal("A private key is required to decrypt data")
	}

	log.Infof("Encrypting files %s with key %s", files, *privateKey)
}
