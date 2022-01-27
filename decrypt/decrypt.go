package decrypt

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/NBISweden/sda-cli/helpers"
	"github.com/elixir-oslo/crypt4gh/keys"
	log "github.com/sirupsen/logrus"
)

// Help text and command line flags.

// Usage text that will be displayed as command line help text when using the
// `help decrypt` command
var Usage = `
USAGE: %s decrypt (-createKey <name>) -key <private-key-file> [file(s)]

Decrypt: Encrypts files from the Sensitive Data Archive (SDA) with the provided
         private key.
`

// ArgHelp is the suffix text that will be displayed after the argument list in
// the module help
var ArgHelp = `
  [file(s)]
        all flagless arguments will be used as filenames for decryption.`

// Args is a flagset that needs to be exported so that it can be written to the
// main program help
var Args = flag.NewFlagSet("decrypt", flag.ExitOnError)

var keyName = Args.String("createKey", "",
	"Generate a crypt4gh key pair to use for decryption")

var privateKeyFile = Args.String("key", "",
	"Private key to use for decrypting files.")

// Decrypt takes a set of arguments, parses them, and attempts to eiher create a
// crypt4gh key pair (if -keyName is set) or decrypt the given data files with
// the given private key file (otherwise).
func Decrypt(args []string) error {
	err := Args.Parse(os.Args[1:])
	if err != nil {
		return fmt.Errorf("argument parsing failed, reason: %v", err)
	}

	// Args() returns the non-flag arguments, which we assume are filenames.
	files := Args.Args()

	// Create a private key and exit if the -createKey flag is set
	// Currently, no password can be provided.
	if *keyName != "" {
		err := generateKeyPair(*keyName, "")
		if err != nil {
			return fmt.Errorf("failed to generate key pair: %s", err)
		}
		os.Exit(0)
	}

	// Check that we have a private key to decrypt with
	if *privateKeyFile == "" {
		return errors.New("a private key is required to decrypt data")
	}

	// Loading private key file
	_, err = readPrivateKey(*privateKeyFile, "")
	if err != nil {
		return err
	}

	log.Infof("Encrypting files %s with key %s", files, *privateKeyFile)

	return nil
}

// Generates a crypt4gh key pair, and saves it to the `<basename>.pub.pem` and
// `<basename>.sec.pem` files. If any of the files already exists, the function
// will instead return an error.
func generateKeyPair(basename, password string) error {
	privateKeyName := fmt.Sprintf("%s.sec.pem", basename)
	publicKeyName := fmt.Sprintf("%s.pub.pem", basename)

	// check if any of the files exist
	if helpers.FileExists(publicKeyName) {
		return fmt.Errorf("public key file %s already exists", publicKeyName)
	}
	if helpers.FileExists(privateKeyName) {
		return fmt.Errorf("private key file %s already exists", privateKeyName)
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
	pass := []byte(password)
	err = keys.WriteCrypt4GHX25519PrivateKey(secFile, privateKeyData, pass)

	return err
}

// Reads a private key file from a file using the crypt4gh keys module
func readPrivateKey(filename, password string) (key *[32]byte, err error) {

	// Check that the file exists
	if !helpers.FileExists(filename) {
		return nil, fmt.Errorf("private key file %s doesn't exist", filename)
	}

	log.Info("Reading Private key file")
	file, err := os.Open(filepath.Clean(filename))
	if err != nil {
		return nil, err
	}

	// This function panics if the key is malformed, so we handle that as well
	// as errors
	defer func() {
		if recover() != nil {
			err = fmt.Errorf("malformed key file: %s", filename)
		}
	}()

	privateKey, err := keys.ReadPrivateKey(file, []byte(password))

	return &privateKey, err
}
