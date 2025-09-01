package encrypt

import (
	"bytes"
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/NBISweden/sda-cli/helpers"
	"github.com/NBISweden/sda-cli/login"
	"github.com/neicnordic/crypt4gh/keys"
	"github.com/neicnordic/crypt4gh/streaming"
	"github.com/smallnest/ringbuffer"
	"github.com/vbauerster/mpb/v8"
	"github.com/vbauerster/mpb/v8/decor"
)

// Help text and command line flags.

// Usage text that will be displayed as command line help text when using the
// `help encrypt` command
var Usage = `
Usage: %s encrypt [OPTIONS] [file(s)] 

Encrypt files according to the Crypt4GH standard used in the Sensitive Data
Archive (SDA). Each input file will be encrypted and saved as '<filename>.c4gh'.
Additionally, checksums for both encrypted and unencrypted files will be
calculated and written to the following files:
  - checksum_unencrypted.md5
  - checksum_encrypted.md5
  - checksum_unencrypted.sha256
  - checksum_encrypted.sha256

Important:
  Exactly one of '-key' or '-target' must be specified.

Options:
  -key <public-key-file>   Public key file(s) to use for encryption. This flag can be specified 
                           multiple times to encrypt files with multiple public keys.
                           Key files may contain concatenated keys.
  -target <target>         Client target associated with the public key.
  -outdir <dir>            Output directory for encrypted files. Defaults to the current directory.
  -continue=true|false     Skip files with errors and continue processing others. Defaults to 'false'.

Arguments:
  [file(s)]                List of file paths to be encrypted.
                           All flagless arguments are treated as filenames.`

// Args is a flagset that needs to be exported so that it can be written to the
// main program help
var Args = flag.NewFlagSet("encrypt", flag.ContinueOnError)

var outDir = Args.String("outdir", "",
	"Output directory for encrypted files.")

var continueEncrypt = Args.Bool("continue", false, "Skip files with errors and continue processing others. Defaults to 'false'.")

var target = Args.String("target", "", "Client target associated with the public key.")

var publicKeyFileList []string

func init() {
	Args.Func("key", "Public key file(s) to use for encryption. This flag can be specified\nmultiple times to encrypt files with multiple public keys. \nKey files may contain concatenated keys.", func(s string) error {
		publicKeyFileList = append(publicKeyFileList, s)

		return nil
	})
}

// Encrypt takes a set of arguments, parses them, and attempts to encrypt the
// given data files with the given public key file
func Encrypt(args []string) (err error) {
	var pubKeyList [][32]byte
	// Call ParseArgs to take care of all the flag parsing
	err = helpers.ParseArgs(args, Args)
	if err != nil {
		return err
	}

	switch {
	case publicKeyFileList != nil && *target != "":
		return errors.New("only one of -key or -target can be used")
	case *target != "":
		// fetch info endpoint values
		fmt.Println("fetching public key")
		info, err := login.GetAuthInfo(*target)
		if err != nil {
			return err
		}

		data, err := base64.StdEncoding.DecodeString(info.PublicKey)
		if err != nil {
			return err
		}

		pubkey, err := keys.ReadPublicKey(bytes.NewReader(data))
		if err != nil {
			return err
		}

		pubKeyList = append(pubKeyList, pubkey)
	case publicKeyFileList == nil:
		// check for public key in .sda-cli-session file from login
		pubKey, err := helpers.GetPublicKeyFromSession()
		if err != nil {
			return err
		}

		if pubKey == "" {
			return errors.New("no public key supplied")
		}

		publicKeyFileList = append(publicKeyFileList, pubKey)
	default:
		// Read the public key(s) to be used for encryption. The matching private key will be able to decrypt the file.
		pubKeyList, err = createPubKeyList(publicKeyFileList, newKeySpecs())
		if err != nil {
			return err
		}
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
			filesSkippedError := fmt.Errorf("(%d/%d) files skipped", skippedFiles, len(files)+skippedFiles)
			err = errors.Join(err, filesSkippedError)
		}
	}()

	// Args() returns the non-flag arguments, which we assume are filenames.
	fmt.Println("Checking files")
	for _, filename := range Args.Args() {
		// Set directory for the output file
		outFilename := filename + ".c4gh"
		if *outDir != "" {
			_, basename := filepath.Split(filename)
			outFilename = filepath.Join(*outDir, basename) + ".c4gh"
		}

		eachFile[0] = helpers.EncryptionFileSet{Unencrypted: filename, Encrypted: outFilename}

		// Skip files that do not pass the checks and print all error logs at the end
		if err = checkFiles(eachFile); err != nil {
			defer fmt.Fprintf(os.Stderr, "Skipping input file %s. Reason: %v.\n", filename, err)
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

	fmt.Printf("Ready to encrypt %d file(s)\n", len(files))

	// Generate a random private key to encrypt the data
	privateKey, err := generatePrivateKey()
	if err != nil {
		return err
	}

	// Open all checksum files
	checksumFileUnencMd5, err := os.OpenFile("checksum_unencrypted.md5", os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		return err
	}
	defer func() {
		if err := checksumFileUnencMd5.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "Error closing file: %v\n", err)
		}
	}()

	checksumFileUnencSha256, err := os.OpenFile("checksum_unencrypted.sha256", os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		return err
	}
	defer func() {
		if err := checksumFileUnencSha256.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "Error closing file: %v\n", err)
		}
	}()

	checksumFileEncMd5, err := os.OpenFile("checksum_encrypted.md5", os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		return err
	}
	defer func() {
		if err := checksumFileEncMd5.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "Error closing file: %v\n", err)
		}
	}()

	checksumFileEncSha256, err := os.OpenFile("checksum_encrypted.sha256", os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		return err
	}
	defer func() {
		if err := checksumFileEncSha256.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "Error closing file: %v\n", err)
		}
	}()

	// encrypt the input files
	numFiles := len(files)
	for i, file := range files {
		fmt.Printf("Encrypting file %v/%v: %s\n", i+1, numFiles, file.Unencrypted)

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
		if _, err := fmt.Fprintf(checksumFileUnencMd5, "%s %s\n", hashes.unencryptedMd5, file.Unencrypted); err != nil {
			return err
		}

		if _, err := fmt.Fprintf(checksumFileUnencSha256, "%s %s\n", hashes.unencryptedSha256, file.Unencrypted); err != nil {
			return err
		}

		if _, err := fmt.Fprintf(checksumFileEncMd5, "%s %s\n", hashes.encryptedMd5, file.Encrypted); err != nil {
			return err
		}

		if _, err := fmt.Fprintf(checksumFileEncSha256, "%s %s\n", hashes.encryptedSha256, file.Encrypted); err != nil {
			return err
		}
	}

	return err
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
				fmt.Fprintf(os.Stderr, "Error closing file: %v\n", err)
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
			fmt.Fprintf(os.Stderr, "Error closing file: %v\n", err)
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
			fmt.Fprintf(os.Stderr, "Error closing file: %v\n", err)
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

// Reads a public key from a file using the crypt4gh keys module
func readPublicKeyFile(filename string) (key *[32]byte, err error) {
	fmt.Println("Reading Public key file")
	file, err := os.Open(filepath.Clean(filename))
	if err != nil {
		return nil, err
	}
	defer file.Close()

	publicKey, err := keys.ReadPublicKey(file)
	if err != nil {
		return nil, fmt.Errorf(err.Error()+", file: %s", filename)
	}

	return &publicKey, err
}

// Reads multiple public keys from a file using the crypt4gh keys module and
// returns them in a list.
func readMultiPublicKeyFile(filename string, k keySpecs) (key *[][32]byte, err error) {
	file, err := os.ReadFile(filepath.Clean(filename))
	if err != nil {
		return nil, err
	}

	m := k.rgx.FindAllString(string(file), -1)

	fmt.Printf("Reading %d concatenated Public keys from file\n", len(m))

	var list [][32]byte
	for _, keyString := range m {
		newKey := strings.NewReader(keyString)

		publicKey, err := keys.ReadPublicKey(newKey)
		if err != nil {
			return nil, fmt.Errorf(err.Error()+", file: %s", filename)
		}

		list = append(list, publicKey)
	}

	if len(list) == 0 {
		return nil, fmt.Errorf("no public keys found in file: %s", filename)
	}

	return &list, err
}

// Generates a crypt4gh key pair, returning only the private key, as the
// public key used for encryption is the one provided as an argument.
func generatePrivateKey() (*[32]byte, error) {
	fmt.Println("Generating encryption key")

	_, privateKey, err := keys.GenerateKeyPair()
	if err != nil {
		return nil, errors.New("failed to generate private key for encryption")
	}

	return &privateKey, nil
}

// Encrypts the data from `filename` into `outFilename` for the given `pubKey`,
// using the given `privateKey`.
func encrypt(filename, outFilename string, pubKeyList [][32]byte, privateKey [32]byte) error {
	// create new progressbar instance
	p := mpb.New()

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
			fmt.Fprintf(os.Stderr, "Error closing file: %v\n", err)
		}
	}()

	// open outfile for writing
	outFile, err := os.Create(filepath.Clean(outFilename))
	if err != nil {
		return err
	}
	defer func() {
		if err := outFile.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "Error closing file: %v\n", err)
		}
	}()

	// Create crypt4gh writer

	crypt4GHWriter, err := streaming.NewCrypt4GHWriter(outFile,
		privateKey, pubKeyList, nil)
	if err != nil {
		return err
	}
	defer crypt4GHWriter.Close() //nolint:errcheck

	fileInfo, err := inFile.Stat()
	if err != nil {
		return err
	}

	// Create a mpb *Bar so we can track encryption progress with one progress bar per file being encrypted
	bar := p.AddBar(fileInfo.Size(),
		mpb.PrependDecorators(
			decor.Name(inFile.Name(), decor.WC{W: len(inFile.Name()) + 1, C: decor.DindentRight}),
			decor.Name("encrypting", decor.WCSyncSpaceR),
			decor.Counters(decor.SizeB1024(0), "% .1f / % .1f"),
		),
		mpb.AppendDecorators(
			decor.OnComplete(decor.Percentage(decor.WC{W: 5}), "done"),
		),
	)

	// Encrypt the data
	_, err = io.Copy(crypt4GHWriter, bar.ProxyReader(inFile))
	if err != nil {
		return err
	}

	p.Wait()

	return nil
}

// Checks the first n bytes of a file for text matching the given regex pattern.
// If a match is found then the byte size of the file is returned.
func checkKeyFile(pubkey string, k keySpecs) (int64, error) {
	f, err := os.Open(pubkey)
	if err != nil {
		return 0, err
	}
	defer func() {
		if err := f.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "Error closing file: %v\n", err)
		}
	}()

	b := make([]byte, k.nbytes)
	if _, err = f.Read(b); err != nil {
		return 0, err
	}
	match := k.rgx.MatchString(string(b))

	if !match {
		return 0, fmt.Errorf("invalid key format in file: %s", pubkey)
	}

	// get file size
	fs, err := f.Stat()
	if err != nil {
		return 0, err
	}

	return fs.Size(), nil
}

// EmptyPublicKeyFileList cleans the publicKeyFileList
// main use case is in unit tests when files are to be encrypted with different keys in different invocations
func EmptyPublicKeyFileList() {
	publicKeyFileList = make([]string, 0)
}

// Takes a key file list and specs about the expected key and returns the parsed public key(s)
// in a list ready to be used by crypt4gh package
func createPubKeyList(publicKeyFileList []string, c4ghKeySpecs keySpecs) ([][32]byte, error) {
	pubKeyList := [][32]byte{}

	for _, pubkey := range publicKeyFileList {
		// Check that pub key file(s) have a valid format. This ensures that some large
		// datafile is not read in by user's mistake before we read in the whole file below.
		fileSize, err := checkKeyFile(pubkey, c4ghKeySpecs)
		if err != nil {
			return nil, err
		}

		// If file contains concatenated pub keys, parse them in a list, append the list and move along.
		if fileSize > int64(c4ghKeySpecs.nbytes) {
			publicKeys, err := readMultiPublicKeyFile(pubkey, c4ghKeySpecs)
			if err != nil {
				return nil, err
			}
			pubKeyList = append(pubKeyList, *publicKeys...)

			continue
		}

		publicKey, err := readPublicKeyFile(pubkey)
		if err != nil {
			return nil, err
		}
		pubKeyList = append(pubKeyList, *publicKey)
	}

	return pubKeyList, nil
}

func newKeySpecs() keySpecs {
	return keySpecs{
		rgx:    regexp.MustCompile(`-{5}BEGIN CRYPT4GH PUBLIC KEY-{5}\n.*\n-{5}END CRYPT4GH PUBLIC KEY-{5}`),
		nbytes: 115,
	}
}

// struct to keep track of all the checksums for a given unencrypted input file.
type hashSet struct {
	encryptedMd5      string
	unencryptedMd5    string
	encryptedSha256   string
	unencryptedSha256 string
}

type keySpecs struct {
	rgx    *regexp.Regexp // text pattern to match
	nbytes int            // first n bytes of file to parse
}

func Stream(file *os.File, pubKeyList [][32]byte) (FileStream, error) {
	if len(pubKeyList) == 0 {
		return FileStream{}, errors.New("no public key supplied")
	}
	privateKey, err := generatePrivateKey()
	if err != nil {
		return FileStream{}, err
	}

	unencryptedMD5 := md5.New()
	unencryptedSha256 := sha256.New()
	unecryptedWriter := io.MultiWriter(unencryptedMD5, unencryptedSha256)
	unencryptedReader := io.TeeReader(file, unecryptedWriter)

	encryptedData := ringbuffer.New(1024 * 1024).SetBlocking(true)
	encryptedMD5 := md5.New()
	encryptedSha256 := sha256.New()
	encryptedWriter := io.MultiWriter(encryptedData, encryptedMD5, encryptedSha256)

	crypt4GHWriter, err := streaming.NewCrypt4GHWriter(encryptedWriter, *privateKey, pubKeyList, nil)
	if err != nil {
		return FileStream{}, err
	}
	go func() {
		_, err := io.Copy(crypt4GHWriter, unencryptedReader)
		if err != nil {
			encryptedData.CloseWithError(err)
		}

		err = crypt4GHWriter.Close()
		if err != nil {
			encryptedData.CloseWithError(err)
		}

		encryptedData.CloseWriter()
	}()

	fs := FileStream{
		EncryptedMD5:      encryptedMD5,
		EncryptedSha256:   encryptedSha256,
		Reader:            encryptedData.ReadCloser(),
		UnencryptedMD5:    unencryptedMD5,
		UnencryptedSha256: unencryptedSha256,
	}

	return fs, nil
}

type FileStream struct {
	EncryptedMD5      hash.Hash
	EncryptedSha256   hash.Hash
	Reader            io.ReadCloser
	UnencryptedMD5    hash.Hash
	UnencryptedSha256 hash.Hash
}
