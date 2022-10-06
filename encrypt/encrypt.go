package encrypt

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"

	"github.com/NBISweden/sda-cli/helpers"

	"github.com/neicnordic/crypt4gh/keys"
	"github.com/neicnordic/crypt4gh/streaming"
	log "github.com/sirupsen/logrus"
)

// Help text and command line flags.

// Usage text that will be displayed as command line help text when using the
// `help encrypt` command
var Usage = `
USAGE: %s encrypt -key <public-key-file> (-outdir <dir>) (-continue=true) [file(s)]

encrypt: Encrypts files according to the crypt4gh standard used in the Sensitive
         Data Archive (SDA). Each given file will be encrypted and written to
         <filename>.c4gh. Both encrypted and unencrypted checksums will be
         calculated and written to:
          - checksum_unencrypted.md5
          - checksum_encrypted.md5
          - checksum_unencrypted.sha256
          - checksum_encrypted.sha256
`

// ArgHelp is the suffix text that will be displayed after the argument list in
// the module help
var ArgHelp = `
  [files]
        all flagless arguments will be used as filenames for encryption.`

// Args is a flagset that needs to be exported so that it can be written to the
// main program help
var Args = flag.NewFlagSet("encrypt", flag.ExitOnError)

var outDir = Args.String("outdir", "", "Output directory for encrypted files")

var continueEncrypt = Args.Bool("continue", false, "Do not exit on file errors but skip and continue.")

var publicKeyFileList []string

func init() {
	Args.Func("key", "Public key file(s) to use for encryption. \nUse multiple times to encrypt with multiple public keys", func(s string) error {
		publicKeyFileList = append(publicKeyFileList, s)
		return nil
	})
}

// Encrypt takes a set of arguments, parses them, and attempts to encrypt the
// given data files with the given public key file
func Encrypt(args []string) error {
	// Parse flags.
	err := Args.Parse(args[1:])
	if err != nil {
		return fmt.Errorf("could not parse arguments: %s", err)
	}

	// Exit if public key is not provided
	if len(publicKeyFileList) == 0 {
		return fmt.Errorf("public key not provided")
	}

	// Each filename is first read into a helper struct (sliced for combatibility with checkFiles)
	eachFile := make([]helpers.EncryptionFileSet, 1)

	// All filenames that pass the checks are read into a struct together with their output filenames
	files := []helpers.EncryptionFileSet{}

	// Counter for skipped files
	skippedFiles := 0

	// Make sure to exit with error status if any file is skipped
	defer func() {
		if skippedFiles != 0 {
			log.Errorf("(%d/%d) files skipped", skippedFiles, len(files)+skippedFiles)
			os.Exit(1)
		}
	}()

	// Args() returns the non-flag arguments, which we assume are filenames.
	log.Info("Checking files")
	for _, filename := range Args.Args() {

		// Set directory for the output file
		outFilename := filename + ".c4gh"
		if *outDir != "" {
			_, basename := path.Split(filename)
			outFilename = path.Join(*outDir, basename) + ".c4gh"
		}

		eachFile[0] = helpers.EncryptionFileSet{Unencrypted: filename, Encrypted: outFilename}

		// Skip files that do not pass the checks and print all error logs at the end
		if err = checkFiles(eachFile); err != nil {
			defer log.Errorf("Skipping input file %s. Reason: %s.", filename, err)
			if !*continueEncrypt {
				return fmt.Errorf("aborting")
			}
			skippedFiles++

			continue
		}

		files = append(files, eachFile[0])
	}

	// exit if files slice is empty
	if len(files) == 0 {
		return fmt.Errorf("no input files")
	}

	log.Infof("Ready to encrypt %d file(s)", len(files))

	// Read the public key(s) to be used for encryption. The matching private
	// key will be able to decrypt the file.
	pubKeyList := [][32]byte{}
	for _, pubkey := range publicKeyFileList {
		publicKey, err := readPublicKey(pubkey)
		if err != nil {
			return err
		}
		pubKeyList = append(pubKeyList, *publicKey)
		fmt.Println(pubKeyList)
	}

	// Generate a random private key to encrypt the data
	privateKey, err := generatePrivateKey()
	if err != nil {
		return err
	}

	// Open all checksum files
	ChecksumFileUnencMd5, err := os.OpenFile("checksum_unencrypted.md5", os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		return err
	}
	defer func() {
		if err := ChecksumFileUnencMd5.Close(); err != nil {
			log.Errorf("Error closing file: %s\n", err)
		}
	}()

	ChecksumFileUnencSha256, err := os.OpenFile("checksum_unencrypted.sha256", os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		return err
	}
	defer func() {
		if err := ChecksumFileUnencSha256.Close(); err != nil {
			log.Errorf("Error closing file: %s\n", err)
		}
	}()

	ChecksumFileEncMd5, err := os.OpenFile("checksum_encrypted.md5", os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		return err
	}
	defer func() {
		if err := ChecksumFileEncMd5.Close(); err != nil {
			log.Errorf("Error closing file: %s\n", err)
		}
	}()

	ChecksumFileEncSha256, err := os.OpenFile("checksum_encrypted.sha256", os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		return err
	}
	defer func() {
		if err := ChecksumFileEncSha256.Close(); err != nil {
			log.Errorf("Error closing file: %s\n", err)
		}
	}()

	// encrypt the input files
	numFiles := len(files)
	for i, file := range files {
		log.Infof("Encrypting file %v/%v: %s", i+1, numFiles, file.Unencrypted)

		// encrypt the file
		err = encrypt(file.Unencrypted, file.Encrypted, pubKeyList, *privateKey)
		if err != nil {
			return err
		}
		// calculate hashes
		hashes, err := calculateHashes(file)
		if err != nil {
			return err
		}

		// Write hashes
		if _, err := ChecksumFileUnencMd5.WriteString(fmt.Sprintf("%s %s\n", hashes.unencryptedMd5, file.Unencrypted)); err != nil {
			return err
		}

		if _, err := ChecksumFileUnencSha256.WriteString(fmt.Sprintf("%s %s\n", hashes.unencryptedSha256, file.Unencrypted)); err != nil {
			return err
		}

		if _, err := ChecksumFileEncMd5.WriteString(fmt.Sprintf("%s %s\n", hashes.encryptedMd5, file.Encrypted)); err != nil {
			return err
		}

		if _, err := ChecksumFileEncSha256.WriteString(fmt.Sprintf("%s %s\n", hashes.encryptedSha256, file.Encrypted)); err != nil {
			return err
		}
	}

	return nil
}

// Checks that all the input files exist, are readable and not already encrypted,
// and that the output files do not exist
func checkFiles(files []helpers.EncryptionFileSet) error {

	for _, file := range files {
		// check that the input file exists and is readable
		if !helpers.FileIsReadable(file.Unencrypted) {
			return fmt.Errorf("cannot read input file %s", file.Unencrypted)
		}

		// check that the output file doesn't exist
		if helpers.FileExists(file.Encrypted) {
			return fmt.Errorf("outfile %s already exists", file.Encrypted)
		}

		// Check if the input file is already encrypted
		unEncryptedFile, err := os.Open(file.Unencrypted)
		if err != nil {
			return err
		}
		defer func() {
			if err := unEncryptedFile.Close(); err != nil {
				log.Errorf("Error closing file: %s\n", err)
			}
		}()

		// Extracting the first 8 bytes of the header - crypt4gh
		magicWord := make([]byte, 8)
		_, err = unEncryptedFile.Read(magicWord)
		if err != nil {
			return fmt.Errorf("error reading input file %s, reason: %v", file.Unencrypted, err)
		}
		if string(magicWord) == "crypt4gh" {
			return fmt.Errorf("input file %s is already encrypted(.c4gh)", file.Unencrypted)
		}
	}

	return nil
}

// Calculates md5 and sha256 hashes for the unencrypted and encrypted files
func calculateHashes(fileSet helpers.EncryptionFileSet) (*hashSet, error) {

	hashes := hashSet{"", "", "", ""}

	// open infile
	unencryptedFile, err := os.Open(fileSet.Unencrypted)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := unencryptedFile.Close(); err != nil {
			log.Errorf("Error closing file: %s\n", err)
		}
	}()

	// unencrypted md5 and sha256 checksums
	md5Hash := md5.New()
	shaHash := sha256.New()

	tee := io.TeeReader(unencryptedFile, md5Hash)

	_, err = io.Copy(shaHash, tee)
	if err != nil {
		return nil, err
	}
	hashes.unencryptedMd5 = hex.EncodeToString(md5Hash.Sum(nil))
	hashes.unencryptedSha256 = hex.EncodeToString(shaHash.Sum(nil))

	// encrypted md5 and sha256 checksums
	encryptedFile, err := os.Open(fileSet.Encrypted)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := encryptedFile.Close(); err != nil {
			log.Errorf("Error closing file: %s\n", err)
		}
	}()

	// encrypted md5
	md5Hash.Reset()
	shaHash.Reset()

	tee = io.TeeReader(encryptedFile, md5Hash)
	_, err = io.Copy(shaHash, tee)
	if err != nil {
		return nil, err
	}
	hashes.encryptedMd5 = hex.EncodeToString(md5Hash.Sum(nil))
	hashes.encryptedSha256 = hex.EncodeToString(shaHash.Sum(nil))

	return &hashes, nil
}

// Reads a public key file from a file using the crypt4gh keys module
func readPublicKey(filename string) (key *[32]byte, err error) {
	log.Info("Reading Public key file")
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

	publicKey, err := keys.ReadPublicKey(file)

	return &publicKey, err
}

// Generates a crypt4gh key pair, returning only the private key, as the
// public key used for encryption is the one provided as an argument.
func generatePrivateKey() (*[32]byte, error) {
	log.Info("Generating encryption key")

	_, privateKey, err := keys.GenerateKeyPair()
	if err != nil {
		return nil, errors.New("failed to generate private key for encryption")
	}

	return &privateKey, nil
}

// Encrypts the data from `filename` into `outFilename` for the given `pubKey`,
// using the given `privateKey`.
func encrypt(filename, outFilename string, pubKeyList [][32]byte, privateKey [32]byte) error {
	// check if outfile exists
	if helpers.FileExists(outFilename) {
		return fmt.Errorf("outfile %s already exists", outFilename)
	}

	// read infile
	inFile, err := os.Open(filepath.Clean(filename))
	if err != nil {
		return err
	}
	defer func() {
		if err := inFile.Close(); err != nil {
			log.Errorf("Error closing file: %s\n", err)
		}
	}()

	// open outfile for writing
	outFile, err := os.Create(filepath.Clean(outFilename))
	if err != nil {
		return err
	}
	defer func() {
		if err := outFile.Close(); err != nil {
			log.Errorf("Error closing file: %s\n", err)
		}
	}()

	// Create crypt4gh writer

	crypt4GHWriter, err := streaming.NewCrypt4GHWriter(outFile,
		privateKey, pubKeyList, nil)
	if err != nil {
		return err
	}
	defer crypt4GHWriter.Close()

	// Encrypt the data
	_, err = io.Copy(crypt4GHWriter, inFile)
	if err != nil {
		return err
	}

	return nil
}

//
// structs
//

// struct to keep track of all the checksums for a given unencrypted input file.
type hashSet struct {
	encryptedMd5      string
	unencryptedMd5    string
	encryptedSha256   string
	unencryptedSha256 string
}
