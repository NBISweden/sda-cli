package createkey

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/NBISweden/sda-cli/cmd"
	"github.com/NBISweden/sda-cli/helpers"
	"github.com/neicnordic/crypt4gh/keys"
	"github.com/spf13/cobra"
)

var outDir string

var createKeyCmd = &cobra.Command{
	Use:   "createKey [OPTIONS] <name>",
	Short: "Generate a Crypt4GH key pair",
	Long: `Generate a Crypt4GH encryption key pair and save the keys as :
	- <name>.pub.pem (public key)
	- <name>.sec.pem (private key)

	Important:
		Keys generated with this command are intended for decrypting files 
		downloaded from the archive. They should NOT be used for encrypting 
		submission files.`,
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) > 1 {
			return fmt.Errorf("unknown arguments: %v, expected a single filename", strings.Join(args, ", "))
		}
		if len(args) < 1 {
			return errors.New("no filename given")
		}

		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		err := CreateKey(args[0])
		if err != nil {
			return err
		}

		return nil
	},
}

func init() {
	cmd.AddCommand(createKeyCmd)
	createKeyCmd.Flags().StringVar(&outDir, "outdir", "", "The directory where the generated keys will be saved. If not specified, the current directory is used")
}

// Generate a keyfile with given basename and password
func CreateKey(basename string) error {
	basename = filepath.Join(outDir, basename)
	password, err := helpers.PromptPassword("Enter private key password")

	if err != nil {
		return fmt.Errorf("failed to read password from user: %v", err)
	}

	err = GenerateKeyPair(basename, password)

	return err
}

// Generates a crypt4gh key pair and saves it to
// `<basename>.pub.pem` and `<basename>.sec.pem`. If any of the files
// already exists, the function will instead return an error.
func GenerateKeyPair(basename, password string) error {
	privateKeyName := fmt.Sprintf("%s.sec.pem", basename)
	publicKeyName := fmt.Sprintf("%s.pub.pem", basename)

	if helpers.FileExists(publicKeyName) || helpers.FileExists(privateKeyName) {
		return fmt.Errorf("key pair with name '%v' seems to already exist, refusing to overwrite", basename)
	}

	fmt.Printf("Generating key pair: %s, %s\n", privateKeyName, publicKeyName)
	publicKeyData, privateKeyData, err := keys.GenerateKeyPair()
	if err != nil {
		return err
	}

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
