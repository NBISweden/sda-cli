package encrypt

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
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

// Type to keep track of infiles and outfiles
type encryptionFileSet struct {
	unencrypted string
	encrypted   string
}

type hashSet struct {
	encryptedMd5      string
	unencryptedMd5    string
	encryptedSha256   string
	unencryptedSha256 string
}

// Main encryption function
func Encrypt(args []string) {

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
		log.Fatal(err)
	}

	// Read the public key to be used for encryption. The private key
	// matching this public key will be able to decrypt the file.
	publicKey, err := readPublicKey(*publicKeyFile)
	if err != nil {
		log.Fatal(err)
	}

	// Generate a random private key to encrypt the data
	privateKey, err := generatePrivateKey()
	if err != nil {
		log.Fatal(err)
	}

	// Open all checksum files
	ChecksumFileUnencMd5, err := os.OpenFile("checksum_unencrypted.md5",
		os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		log.Fatal(err)
	}
	defer ChecksumFileUnencMd5.Close()

	ChecksumFileUnencSha256, err := os.OpenFile("checksum_unencrypted.sha256",
		os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		log.Fatal(err)
	}
	defer ChecksumFileUnencSha256.Close()

	ChecksumFileEncMd5, err := os.OpenFile("checksum_encrypted.md5",
		os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		log.Fatal(err)
	}
	defer ChecksumFileEncMd5.Close()

	ChecksumFileEncSha256, err := os.OpenFile("checksum_encrypted.sha256",
		os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		log.Fatal(err)
	}
	defer ChecksumFileEncSha256.Close()

	// encrypt the input files
	num_files := len(files)
	for i, file := range files {
		log.Infof("Encrypting file %v/%v: %s", i+1, num_files, file.unencrypted)

		// encrypt the file
		err = encrypt(file.unencrypted, file.encrypted, *publicKey, *privateKey)
		if err != nil {
			log.Fatal(err)
		}
		// calculate hashes
		hashes, err := calculateHashes(file)
		if err != nil {
			log.Fatal(err)
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
}

// Checks that all the input files exists, and are readable
func checkFiles(files []encryptionFileSet) error {
	log.Info("Checking files")
	for _, file := range files {
		// check that the input file exists
		fileInfo, err := os.Stat(file.unencrypted)
		if err != nil {
			return err
		}
		// check that the input file isn't a directory
		if fileInfo.IsDir() {
			return fmt.Errorf("%s is a directory", file.unencrypted)
		}
		// check that the output file doesn't exist
		_, err = os.Stat(file.encrypted)
		if err == nil {
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
func readPublicKey(filename string) (*[32]byte, error) {
	log.Info("Reading Public key file")
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	publicKey, err := keys.ReadPublicKey(file)
	if err != nil {
		return nil, err
	}
	return &publicKey, nil
}

// Generates a crypt4gh key pair, returning only the private key, as the
// public key isn't needed for encryption.
func generatePrivateKey() (*[32]byte, error) {
	log.Info("Generating encryption key")

	_, privateKey, err := keys.GenerateKeyPair()
	if err != nil {
		return nil, err
	}
	return &privateKey, nil
}

// Encrypts the data from `filename` into `outFilename` for the given `pubKey`,
// using the given `privateKey`.
func encrypt(filename, outFilename string, pubKey, privateKey [32]byte) error {
	// check if outfile exists
	if _, err := os.Stat(outFilename); err == nil {
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
