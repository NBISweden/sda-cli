package encrypt

import (
	"flag"
	"os"

	log "github.com/sirupsen/logrus"
)

// Help text and command line flags.

var Usage = `
USAGE: %s encrypt [file(s)]

Encrypt: Encrypts files according to the crypt4gh standard used in the Sensitive
         Data Archive (SDA). Each given file will be encrypted and written to
         <filename>.c4gh. Both encrypted and decrypted checksums will be
         calculated and written to:
          - checksum_decrypted.md5
          - checksum_encrypted.md5
          - checksum_decrypted.sha256
          - checksum_encrypted.sha256
`
var ArgHelp = `
  [files]
        all flagless arguments will be used as filenames for encryption.`

var Args = flag.NewFlagSet("encrypt", flag.ExitOnError)

// Main encryption function
func Encrypt(args []string) {
	// Parse flags. There are no flags at the moment, but in case some are added
	// we check for them.
	Args.Parse(os.Args[1:])

	// Args() returns the non-flag arguments, which we assume are filenames.
	files := Args.Args()

	log.Infof("Encrypting files: %s", files)
}
