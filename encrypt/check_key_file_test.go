package encrypt

import (
	"fmt"
	"os"
	"testing"

	"github.com/neicnordic/crypt4gh/keys"
	"github.com/stretchr/testify/assert"
)

func TestCheckKeyFile(t *testing.T) {
	specs := newKeySpecs()

	tempDir := t.TempDir()

	// Generate a crypt4gh key pair
	pubKeyData, _, err := keys.GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate key pair: %v", err)
	}

	// Write the keys to temporary files
	publicKey, err := os.CreateTemp(tempDir, "pubkey-")
	if err != nil {
		t.Fatalf("failed to create temp public key test file: %v", err)
	}

	if err = keys.WriteCrypt4GHX25519PublicKey(publicKey, pubKeyData); err != nil {
		t.Fatalf("failed to write to public key test file: %v", err)
	}
	_ = publicKey.Close()

	multiPublicKey, err := os.CreateTemp(tempDir, "multi-pubkey-")
	if err != nil {
		t.Fatalf("failed to create multi pub key test file: %v", err)
	}

	input, err := os.ReadFile(publicKey.Name())
	if err != nil {
		t.Fatalf("failed to read public key file: %v", err)
	}

	if _, err := multiPublicKey.Write(append(input, input...)); err != nil {
		t.Fatalf("failed to write to multi public key test file: %v", err)
	}
	_ = multiPublicKey.Close()

	notAKeyFile := fmt.Sprintf("%v/not_a_key", tempDir)
	if err := os.WriteFile(notAKeyFile, []byte("not a key file"), 0600); err != nil {
		t.Fatalf("failed to write to not a key file: %v", err)
	}

	_, notFoundError := os.Open("file-not-exists")

	for _, test := range []struct {
		testName        string
		pubKeyFileName  string
		expectedKeySize int64
		expectedError   error
	}{
		{
			testName:        "MultiPubKey",
			pubKeyFileName:  multiPublicKey.Name(),
			expectedKeySize: int64(230),
			expectedError:   nil,
		}, {
			testName:        "PubKey",
			pubKeyFileName:  publicKey.Name(),
			expectedKeySize: int64(115),
			expectedError:   nil,
		}, {
			testName:        "FileDoesNotExist",
			pubKeyFileName:  "file-not-exists",
			expectedKeySize: int64(0),
			expectedError:   notFoundError,
		}, {
			testName:        "NotAKeyFile",
			pubKeyFileName:  notAKeyFile,
			expectedKeySize: int64(0),
			expectedError:   fmt.Errorf("invalid key format in file: %v", notAKeyFile),
		},
	} {
		t.Run(test.testName, func(t *testing.T) {
			keySize, err := checkKeyFile(test.pubKeyFileName, specs)
			assert.Equal(t, test.expectedError, err)
			assert.Equal(t, test.expectedKeySize, keySize)

		})
	}
}
