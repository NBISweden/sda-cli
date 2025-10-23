package decrypt

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/NBISweden/sda-cli/cmd"
	"github.com/NBISweden/sda-cli/helpers"
	"github.com/neicnordic/crypt4gh/keys"
	"github.com/neicnordic/crypt4gh/streaming"
	"github.com/spf13/cobra"
)

var privateKeyFile string
var forceOverwrite bool
var clean bool

var decryptCmd = &cobra.Command{
	Use:   "decrypt [flags] [file(s)]",
	Short: "Decryt files from the SDA",
	Long: ` Decrypt files from the Sensitive Data Archive (SDA) using the specified private key.
	If the private key is password-protected, the password can be provided via the
	C4GH_PASSWORD environment variable or an interactive password prompt.`,
	Args: func(cmd *cobra.Command, args []string) error {
		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		err := Decrypt(args)
		if err != nil {
			return err
		}

		return nil
	},
}

func init() {
	cmd.AddCommand(decryptCmd)
	decryptCmd.Flags().StringVar(&privateKeyFile, "key", "", "Private key to use for decryption")
	decryptCmd.Flags().BoolVar(&forceOverwrite, "force-overwrite", false, "Force overwrite existing files")
	decryptCmd.Flags().BoolVar(&clean, "clean", false, "Remove the encrypted file after decryption")
}

// Needed for testing: used when calling the decrypt from the encrypt pacakge in encrypt_test.go
func SetFlags(key string, value string) {
	decryptCmd.Flag(key).Value.Set(value)
}

// Decrypt takes a set of arguments, parses them, and attempts to decrypt the
// given data files with the given private key file..
func Decrypt(args []string) error {
	files := []helpers.EncryptionFileSet{}
	for _, filename := range args {
		// Set directory for the output file
		unencryptedFilename := strings.TrimSuffix(filename, ".c4gh")
		files = append(files, helpers.EncryptionFileSet{Encrypted: filename, Unencrypted: unencryptedFilename})
	}

	// Check that we have a private key to decrypt with
	if privateKeyFile == "" {
		return errors.New("a private key is required to decrypt data")
	}

	var err error
	password, available := os.LookupEnv("C4GH_PASSWORD")
	if !available {
		password, err = helpers.PromptPassword("Enter password to unlock private key")
		if err != nil {
			return err
		}
	}

	// Loading private key file
	privateKey, err := readPrivateKeyFile(privateKeyFile, password)
	if err != nil {
		return err
	}

	// decrypt the input files
	numFiles := len(files)
	removedCount := 0
	decryptedCount := 0
	for i, file := range files {
		switch {
		case !helpers.FileIsReadable(file.Encrypted):
			fmt.Fprintf(os.Stderr, "Error: cannot read input file %s\n", file.Encrypted)
		case forceOverwrite:
			fmt.Printf("Decrypting file %v/%v: %s\n", i+1, numFiles, file.Encrypted)
			err := decryptFile(file.Encrypted, file.Unencrypted, *privateKey)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error decrypting file %s: %v\n", file.Encrypted, err)

				continue
			}
			decryptedCount++
		case helpers.FileExists(file.Unencrypted):
			fmt.Fprintf(os.Stderr, "Warning: file %s is already decrypted, skipping\n", file.Unencrypted)
		default:
			fmt.Printf("Decrypting file %v/%v: %s\n", i+1, numFiles, file.Encrypted)
			err := decryptFile(file.Encrypted, file.Unencrypted, *privateKey)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error decrypting file %s: %v\n", file.Encrypted, err)

				continue
			}
			decryptedCount++
		}
		// remove the encrypted file if the clean flag is set
		if clean {
			err = os.Remove(file.Encrypted)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Could not remove encrypted file %s: %v\n", file.Encrypted, err)

				continue
			}
			removedCount++
		}
	}
	if decryptedCount != numFiles {
		fmt.Printf("WARNING: %v file(s) could not be decrypted\n", numFiles-decryptedCount)
	}
	if clean && removedCount != numFiles {
		fmt.Printf("WARNING: %v file(s) could not be removed\n", numFiles-removedCount)
	}

	return nil
}

// Reads a private key file from a file using the crypt4gh keys module
func readPrivateKeyFile(filename, password string) (key *[32]byte, err error) {
	// Check that the file exists
	if !helpers.FileExists(filename) {
		return nil, fmt.Errorf("private key file %s doesn't exist", filename)
	}

	file, err := os.Open(filepath.Clean(filename))
	if err != nil {
		return nil, err
	}
	defer file.Close()

	privateKey, err := keys.ReadPrivateKey(file, []byte(password))
	if err != nil {
		return nil, fmt.Errorf(err.Error()+", file: %s", filename)
	}

	return &privateKey, err
}

// decrypts the data in `filename` with the given `privateKey`, writing the
// resulting data to `outfile`.
func decryptFile(filename, outfileName string, privateKey [32]byte) error {
	// open input file for reading
	inFile, err := os.Open(filepath.Clean(filename))
	if err != nil {
		return err
	}
	defer inFile.Close() //nolint:errcheck

	// Create crypt4gh reader
	crypt4GHReader, err := streaming.NewCrypt4GHReader(inFile, privateKey, nil)
	if err != nil {
		return fmt.Errorf("could not create cryp4gh reader: %v", err)
	}
	defer crypt4GHReader.Close()

	// open output file for writing
	outFile, err := os.Create(filepath.Clean(outfileName))
	if err != nil {
		return fmt.Errorf("could not create output file %s: %s", outfileName, err)
	}
	defer outFile.Close()

	_, err = io.Copy(outFile, crypt4GHReader)
	if err != nil {
		return fmt.Errorf("could not decrypt file %s: %s", filename, err)
	}

	return nil
}
