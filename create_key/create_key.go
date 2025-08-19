package createkey

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/NBISweden/sda-cli/helpers"
	"github.com/neicnordic/crypt4gh/keys"
)

// Usage text that will be displayed when the `help createKey` command is invoked.
var Usage = `
Usage: %s createKey [OPTIONS] <name>

Generate a Crypt4GH encryption key pair and saves the keys as:
  - <name>.pub.pem (public key)
  - <name>.sec.pem (private key)

Important:
  Keys generated with this command are intended for decrypting files 
  downloaded from the archive. They should NOT be used for encrypting 
  submission files.

Options:
  -outdir <dirname>  Directory where the generated keys will be saved. 
                     If not specified, the current directory is used.

Arguments:
    <name>           The basename of the keyfiles to generate.`

// Args is a flagset that needs to be exported so that it can be written to the
// main program help
var Args = flag.NewFlagSet("createKey", flag.ExitOnError)

var outDir = Args.String("outdir", "",
	"Output directory for the key files.")

// CreateKey takes two arguments, a base filename, and optionally an output
// directory specified with `-outdir`.
func CreateKey(args []string) error {
	// Parse flags. There are no flags at the moment, but in case some are added
	// we check for them.
	err := Args.Parse(args[1:])
	if err != nil {
		return fmt.Errorf("could not parse arguments: %v", err)
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
	fmt.Printf("Generating key pair: %s, %s\n", privateKeyName, publicKeyName)

	publicKeyData, privateKeyData, err := keys.GenerateKeyPair()
	if err != nil {
		return err
	}

	// Save keys to file
	pubFile, err := os.OpenFile(filepath.Clean(publicKeyName), os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		return err
	}
	defer func() {
		if err := pubFile.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "Error closing file: %v\n", err)
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
			fmt.Fprintf(os.Stderr, "Error closing file: %v\n", err)
		}
	}()
	err = keys.WriteCrypt4GHX25519PrivateKey(secFile, privateKeyData, []byte(password))

	return err
}
