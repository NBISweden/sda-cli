package encrypt

import (
	"os"
	"testing"

	"github.com/neicnordic/crypt4gh/keys"
	"github.com/stretchr/testify/assert"
)

func TestReadPublicKeyFile(t *testing.T) {
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

	_, notFoundError := os.Open("file-not-exists")

	for _, test := range []struct {
		testName            string
		pubKeyFileName      string
		expectedFileContent *[32]byte
		expectedError       error
	}{
		{
			testName:            "FileExists",
			pubKeyFileName:      publicKey.Name(),
			expectedError:       nil,
			expectedFileContent: &pubKeyData,
		}, {
			testName:            "FileDoesNotExist",
			pubKeyFileName:      "file-not-exists",
			expectedFileContent: nil,
			expectedError:       notFoundError,
		},
	} {
		t.Run(test.testName, func(t *testing.T) {

			publicKey, err := readPublicKeyFile(test.pubKeyFileName)
			assert.Equal(t, test.expectedError, err)
			assert.Equal(t, test.expectedFileContent, publicKey)
		})
	}
}
