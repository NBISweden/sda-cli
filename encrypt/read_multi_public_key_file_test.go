package encrypt

import (
	"os"
	"testing"

	"github.com/neicnordic/crypt4gh/keys"
	"github.com/stretchr/testify/assert"
)

func TestReadMultiPublicKeyFile(t *testing.T) {
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

	_, notFoundError := os.Open("file-not-exists")

	for _, test := range []struct {
		testName            string
		multiPubKeyFileName string
		expectedFileContent *[32]byte
		expectedError       error
	}{
		{
			testName:            "FileExists",
			multiPubKeyFileName: multiPublicKey.Name(),
			expectedError:       nil,
			expectedFileContent: &pubKeyData,
		}, {
			testName:            "FileDoesNotExist",
			multiPubKeyFileName: "file-not-exists",
			expectedFileContent: nil,
			expectedError:       notFoundError,
		},
	} {
		t.Run(test.testName, func(t *testing.T) {
			publicKeys, err := readMultiPublicKeyFile(test.multiPubKeyFileName, specs)
			assert.Equal(t, test.expectedError, err)

			if publicKeys == nil && test.expectedFileContent != nil {
				t.Error(t, "public keys was expected but returned nil")
				t.FailNow()
			}

			if publicKeys == nil {
				return
			}
			for _, key := range *publicKeys {
				assert.Equal(t, *test.expectedFileContent, key)
			}
		})
	}
}
