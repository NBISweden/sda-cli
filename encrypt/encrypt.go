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

	"github.com/elixir-oslo/crypt4gh/keys"
	"github.com/elixir-oslo/crypt4gh/streaming"
	log "github.com/sirupsen/logrus"
)

// Help text and command line flags.

var Usage = `
USAGE: %s encrypt [file(s)]

Encrypt: Encrypts files according to the crypt4gh standard used in the Sensitive
         Data Archive (SDA). Each given file will be encrypted and written to
         <filename>.c4gh. Both encrypted and unencrypted checksums will be
         calculated and written to:
          - checksum_unencrypted.md5
          - checksum_encrypted.md5
          - checksum_unencrypted.sha256
          - checksum_encrypted.sha256
`
var ArgHelp = `
  [files]
        all flagless arguments will be used as filenames for encryption.`

var Args = flag.NewFlagSet("encrypt", flag.ExitOnError)

var publicKeyFile = Args.String("key", "",
	"Public key to use for encrypting files.")
var outDir = Args.String("outdir", "", "Output directory for encrypted files")

// Main encryption function
func Encrypt(args []string) error {

	// Parse flags. There are no flags at the moment, but in case some are added
	// we check for them.
	err := Args.Parse(os.Args[1:])
	if err != nil {
		log.Fatalf("Argument parsing failed, reason: %v", err)
	}

	// Args() returns the non-flag arguments, which we assume are filenames.
	// All filenames are read into a struct together with their output filenames
	files := []encryptionFileSet{}
	for _, filename := range Args.Args() {

		// Set directory for the output file
		outFilename := filename + ".c4gh"
		if *outDir != "" {
			_, basename := path.Split(filename)
			outFilename = path.Join(*outDir, basename) + ".c4gh"
		}

		files = append(files, encryptionFileSet{filename, outFilename})
	}

	// Check that all the infiles exist, and all the outfiles don't
	err := checkFiles(files)
	if err != nil {
		return err
	}

	// Read the public key to be used for encryption. The private key
	// matching this public key will be able to decrypt the file.
	publicKey, err := readPublicKey(*publicKeyFile)
	if err != nil {
		return err
	}

	// Generate a random private key to encrypt the data
	privateKey, err := generatePrivateKey()
	if err != nil {
		return err
	}

	// Open all checksum files
	ChecksumFileUnencMd5, err := os.OpenFile("checksum_unencrypted.md5",
		os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		return err
	}
	defer ChecksumFileUnencMd5.Close()

	ChecksumFileUnencSha256, err := os.OpenFile("checksum_unencrypted.sha256",
		os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		return err
	}
	defer ChecksumFileUnencSha256.Close()

	ChecksumFileEncMd5, err := os.OpenFile("checksum_encrypted.md5",
		os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		return err
	}
	defer ChecksumFileEncMd5.Close()

	ChecksumFileEncSha256, err := os.OpenFile("checksum_encrypted.sha256",
		os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		return err
	}
	defer ChecksumFileEncSha256.Close()

	// encrypt the input files
	num_files := len(files)
	for i, file := range files {
		log.Infof("Encrypting file %v/%v: %s", i+1, num_files, file.unencrypted)

		// encrypt the file
		err = encrypt(file.unencrypted, file.encrypted, *publicKey, *privateKey)
		if err != nil {
			return err
		}
		// calculate hashes
		hashes, err := calculateHashes(file)
		if err != nil {
			return err
		}

		// Write hashes
		ChecksumFileUnencMd5.WriteString(
			fmt.Sprintf("%s %s\n", hashes.unencryptedMd5, file.unencrypted))
		ChecksumFileUnencSha256.WriteString(
			fmt.Sprintf("%s %s\n", hashes.unencryptedSha256, file.unencrypted))
		ChecksumFileEncMd5.WriteString(
			fmt.Sprintf("%s %s\n", hashes.encryptedMd5, file.encrypted))
		ChecksumFileEncSha256.WriteString(
			fmt.Sprintf("%s %s\n", hashes.encryptedSha256, file.encrypted))
	}
	return nil
}

// Checks that all the input files exists, and are readable
func checkFiles(files []encryptionFileSet) error {
	log.Info("Checking files")
	for _, file := range files {
		// check that the input file exists and is readable
		if !FileIsReadable(file.unencrypted) {
			return fmt.Errorf("cannot read input file %s", file.unencrypted)
		}

		// check that the output file doesn't exist
		if FileExists(file.encrypted) {
			return fmt.Errorf("outfile %s already exists", file.encrypted)
		}
	}
	return nil
}

// Calculates md5 and sha256 hashes for the unencrypted and encrypted file
func calculateHashes(fileSet encryptionFileSet) (*hashSet, error) {

	hashes := hashSet{"", "", "", ""}

	// open infile
	unencryptedFile, err := os.Open(fileSet.unencrypted)
	if err != nil {
		return nil, err
	}
	defer unencryptedFile.Close()

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
	encryptedFile, err := os.Open(fileSet.encrypted)
	if err != nil {
		return nil, err
	}
	defer encryptedFile.Close()

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
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}

	// This function panics if the key is malformed, so we handle that as well
	// as errors
	defer func() {
		log.Info("Hey! this is a panic!")
		if recover() != nil {
			err = fmt.Errorf("malformed key file: %s", filename)
		}
	}()

	publicKey, err := keys.ReadPublicKey(file)

	return &publicKey, err
}

// Generates a crypt4gh key pair, returning only the private key, as the
// public key used for encryption is the one provided as argument.
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
func encrypt(filename, outFilename string, pubKey, privateKey [32]byte) error {
	// check if outfile exists
	if FileExists(outFilename) {
		return fmt.Errorf("outfile %s already exists", outFilename)
	}

	// read infile
	inFile, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer inFile.Close()

	// open outfile for writing
	outFile, err := os.Create(outFilename)
	if err != nil {
		return err
	}
	defer outFile.Close()

	// Create crypt4gh writer
	pubKeyList := [][32]byte{pubKey}
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
// Helper functions and structs
//

// struct type to keep track of infiles and outfiles for encryption and
// decryption
type encryptionFileSet struct {
	unencrypted string
	encrypted   string
}

// struct to keep track of all the checksums for a given unencrypted input file.
type hashSet struct {
	encryptedMd5      string
	unencryptedMd5    string
	encryptedSha256   string
	unencryptedSha256 string
}

// Checks if a file exists in the file system. Note that this function will not
// check if the file is readable, or if the file is a directory, only if it
// exists.
func FileExists(filename string) bool {
	_, err := os.Stat(filename)
	return err == nil
}

// Checks that a file exists, and is readable
func FileIsReadable(filename string) bool {
	fileInfo, err := os.Stat(filename)
	if err != nil || fileInfo.IsDir() {
		return false
	}
	// Check readability by simply trying to open the file and read one byte
	inFile, err := os.Open(filename)
	if err != nil {
		return false
	}
	defer inFile.Close()

	test := make([]byte, 1)
	_, err = inFile.Read(test)
	return err == nil
}
