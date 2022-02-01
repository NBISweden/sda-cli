package createKey

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/NBISweden/sda-cli/helpers"
	"github.com/elixir-oslo/crypt4gh/keys"
	log "github.com/sirupsen/logrus"
)

// Help text and command line flags.

// Usage text that will be displayed as command line help text when using the
// `help encrypt` command
var Usage = `
USAGE: %s createKey <name> (-outdir <dirname>)

createKey: Creates a crypt4gh encryption key pair, and saves it to
           <name>.pub.pem, and <name>.sec.pem.
           NOTE: keys created using this function should not be used when
           encrypting submission files, they should only be used for decrypting
           files downloaded from the archive.
`

// ArgHelp is the suffix text that will be displayed after the argument list in
// the module help.
var ArgHelp = ``

// Args is a flagset that needs to be exported so that it can be written to the
// main program help
var Args = flag.NewFlagSet("createKey", flag.ExitOnError)

var outDir = Args.String("outdir", "", "Output directory for the key files")

// CreateKey takes two arguments, a base filename, and optionally an output
// directory specified with `-outdir`.
func CreateKey(args []string) error {

	// Parse flags. There are no flags at the moment, but in case some are added
	// we check for them.
	err := Args.Parse(args[1:])
	if err != nil {
		return fmt.Errorf("could not parse arguments: %s", err)
	}

	// Args() returns the non-flag arguments, which we assume is the key
	// filename. If more than one name is given, an error is returned.
	if len(Args.Args()) > 1 {
		return fmt.Errorf("unknown arguments: %v, expected a single filename", strings.Join(Args.Args(), ", "))
	}
	if len(Args.Args()) < 1 {
		return errors.New("no filename given")
	}
	basename := Args.Args()[0]

	// Add the output directory to the file path (does nothing if outDir is "")
	basename = filepath.Join(*outDir, basename)

	// Read password from user, to avoid having it in plaintext as an argument
	password, err := helpers.PromptPassword("Enter private key password")
	if err != nil {
		return fmt.Errorf("failed to read password from user: %v", err)
	}

	// Write the key files
	err = GenerateKeyPair(basename, password)

	return err
}

// GenerateKeyPair generates a crypt4gh key pair and saves it to the
// `<basename>.pub.pem` and `<basename>.sec.pem` files. If any of the files
// already exists, the function will instead return an error.
func GenerateKeyPair(basename, password string) error {
	privateKeyName := fmt.Sprintf("%s.sec.pem", basename)
	publicKeyName := fmt.Sprintf("%s.pub.pem", basename)

	// check if any of the files exist
	if helpers.FileExists(publicKeyName) || helpers.FileExists(privateKeyName) {
		return fmt.Errorf("key pair with name '%v' seems to already exist, refusing to overwrite", basename)
	}

	// Generate key pair
	log.Infof("Generating key pair: %s, %s", privateKeyName, publicKeyName)

	publicKeyData, privateKeyData, err := keys.GenerateKeyPair()
	if err != nil {
		return err
	}

	// Save keys to file
	pubFile, err := os.OpenFile(filepath.Clean(publicKeyName), os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		return err
	}
	defer func() {
		if err := pubFile.Close(); err != nil {
			log.Errorf("Error closing file: %s\n", err)
		}
	}()
	err = keys.WriteCrypt4GHX25519PublicKey(pubFile, publicKeyData)
	if err != nil {
		return err
	}

	secFile, err := os.OpenFile(filepath.Clean(privateKeyName), os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		return err
	}
	defer func() {
		if err := secFile.Close(); err != nil {
			log.Errorf("Error closing file: %s\n", err)
		}
	}()
	err = keys.WriteCrypt4GHX25519PrivateKey(secFile, privateKeyData, []byte(password))

	return err
}
