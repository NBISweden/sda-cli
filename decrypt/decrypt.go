package decrypt

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/NBISweden/sda-cli/helpers"
	"github.com/elixir-oslo/crypt4gh/keys"
	"github.com/elixir-oslo/crypt4gh/streaming"
	log "github.com/sirupsen/logrus"
)

// Help text and command line flags.

// Usage text that will be displayed as command line help text when using the
// `help decrypt` command
var Usage = `
USAGE: %s decrypt -key <private-key-file> [file(s)]

Decrypt: Encrypts files from the Sensitive Data Archive (SDA) with the provided
         private key. If the private key is encrypted, the password can be
	 supplied in the DECRYPT_PASSWORD environment variable, or at the
	 interactive password prompt.
`

// ArgHelp is the suffix text that will be displayed after the argument list in
// the module help
var ArgHelp = `
  [file(s)]
        all flagless arguments will be used as filenames for decryption.`

// Args is a flagset that needs to be exported so that it can be written to the
// main program help
var Args = flag.NewFlagSet("decrypt", flag.ExitOnError)

var privateKeyFile = Args.String("key", "",
	"Private key to use for decrypting files.")

// Decrypt takes a set of arguments, parses them, and attempts to eiher create a
// crypt4gh key pair (if -keyName is set) or decrypt the given data files with
// the given private key file (otherwise).
func Decrypt(args []string) error {
	err := Args.Parse(args[1:])
	if err != nil {
		return fmt.Errorf("argument parsing failed, reason: %v", err)
	}

	// format input and output files
	// Args() returns the non-flag arguments, which we assume are filenames.
	// All filenames are read into a struct together with their output filenames
	files := []helpers.EncryptionFileSet{}
	for _, filename := range Args.Args() {

		// Set directory for the output file
		unencryptedFilename := strings.TrimSuffix(filename, ".c4gh")

		files = append(files, helpers.EncryptionFileSet{Encrypted: filename, Unencrypted: unencryptedFilename})
	}

	// Check that we have a private key to decrypt with
	if *privateKeyFile == "" {
		return errors.New("a private key is required to decrypt data")
	}

	var privateKey *[32]byte

	// try reading private key without password
	privateKey, err = readPrivateKey(*privateKeyFile, "")
	if err != nil {

		// if there was an error, try again with the password
		password, err := getPassword("DECRYPT_PASSWORD")
		if err != nil {
			return err
		}

		// Loading private key file
		privateKey, err = readPrivateKey(*privateKeyFile, password)
		if err != nil {
			return err
		}
	}

	// Check that all the encrypted files exist, and all the unencrypted don't
	err = checkFiles(files)
	if err != nil {
		return err
	}

	// decrypt the input files
	numFiles := len(files)
	for i, file := range files {
		log.Infof("Decrypting file %v/%v: %s", i+1, numFiles, file.Encrypted)

		err = decrypt(file.Encrypted, file.Unencrypted, *privateKey)
		if err != nil {
			return err
		}
	}

	return nil
}

// getPassword will check if the `envVar` environment variable is set, and
// return its value if present. Otherwise, the password will be read from a user
// prompt.
func getPassword(envVar string) (string, error) {
	// check if there is a password available in the `envVar` env variable
	password, available := os.LookupEnv(envVar)
	if available {
		return password, nil
	}

	// otherwise, read the password from a user prompt
	password, err := helpers.PromptPassword("Enter password to unlock private key")

	return password, err
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

// Checks that all the encrypted files exists, and are readable, and that the
// unencrypted files do not exist
func checkFiles(files []helpers.EncryptionFileSet) error {
	log.Info("Checking files")
	for _, file := range files {
		// check that the input file exists and is readable
		if !helpers.FileIsReadable(file.Encrypted) {
			return fmt.Errorf("cannot read input file %s", file.Encrypted)
		}

		// check that the output file doesn't exist
		if helpers.FileExists(file.Unencrypted) {
			return fmt.Errorf("outfile %s already exists", file.Unencrypted)
		}
	}

	return nil
}

// decrypts the data in `filename` with the given `privateKey`, writing the
// resulting data to `outfile`.
func decrypt(filename, outfileName string, privateKey [32]byte) error {

	// check that the infile exists, and the the outfile doesn't exist
	if !helpers.FileIsReadable(filename) {
		return fmt.Errorf("infile %s does not exist or could not be read", filename)
	}

	if helpers.FileExists(outfileName) {
		return fmt.Errorf("outfile %s already exists", outfileName)
	}

	// open input file for reading
	inFile, err := os.Open(filepath.Clean(filename))
	if err != nil {
		return err
	}
	defer func() {
		if err := inFile.Close(); err != nil {
			log.Errorf("error closing file: %s\n", err)
		}
	}()

	// Create crypt4gh reader
	crypt4GHReader, err := streaming.NewCrypt4GHReader(inFile, privateKey, nil)
	if err != nil {
		return fmt.Errorf("could not create cryp4gh reader: %s", err)
	}

	// open output file for writing
	outFile, err := os.Create(filepath.Clean(outfileName))
	if err != nil {
		return fmt.Errorf("could not create output file %s: %s", outfileName, err)
	}

	_, err = io.Copy(outFile, crypt4GHReader)
	if err != nil {
		return fmt.Errorf("could not decrypt file %s: %s", filename, err)
	}

	return nil
}
