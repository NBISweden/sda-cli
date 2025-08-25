package encrypt

import (
	"fmt"
	"os"
	"testing"

	"github.com/NBISweden/sda-cli/helpers"
	"github.com/stretchr/testify/assert"
)

func TestCalculateHashes(t *testing.T) {
	tempDir := t.TempDir()
	// create an existing test file with some known content
	fileToHash, err := os.CreateTemp(tempDir, "testfile-")
	if err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	if _, err = fileToHash.Write([]byte("content")); err != nil {
		t.Fatalf("failed to write to encrypted input test file: %v", err)
	}
	_ = fileToHash.Close()

	_, notFoundError := os.Open(fmt.Sprintf("%s/does-not-exist", tempDir))

	for _, test := range []struct {
		testName                       string
		unencryptedFile, encryptedFile string
		expectedError                  error
		expectedUnencryptedMd5         string
		expectedUnencryptedSha256      string
		expectedEncryptedMd5           string
		expectedEncryptedSha256        string
	}{
		{
			testName:                  "EncryptedNotExist",
			unencryptedFile:           fileToHash.Name(),
			encryptedFile:             fmt.Sprintf("%s/does-not-exist", tempDir),
			expectedError:             notFoundError,
			expectedUnencryptedMd5:    "",
			expectedUnencryptedSha256: "",
			expectedEncryptedMd5:      "",
			expectedEncryptedSha256:   "",
		}, {
			testName:                  "UnencryptedNotExist",
			unencryptedFile:           fmt.Sprintf("%s/does-not-exist", tempDir),
			encryptedFile:             fileToHash.Name(),
			expectedError:             notFoundError,
			expectedUnencryptedMd5:    "",
			expectedUnencryptedSha256: "",
			expectedEncryptedMd5:      "",
			expectedEncryptedSha256:   "",
		}, {
			testName:                  "BothExist",
			unencryptedFile:           fileToHash.Name(),
			encryptedFile:             fileToHash.Name(),
			expectedError:             nil,
			expectedUnencryptedMd5:    "9a0364b9e99bb480dd25e1f0284c8555",
			expectedUnencryptedSha256: "ed7002b439e9ac845f22357d822bac1444730fbdb6016d3ec9432297b9ec9f73",
			expectedEncryptedMd5:      "9a0364b9e99bb480dd25e1f0284c8555",
			expectedEncryptedSha256:   "ed7002b439e9ac845f22357d822bac1444730fbdb6016d3ec9432297b9ec9f73",
		},
	} {
		t.Run(test.testName, func(t *testing.T) {
			fileSet := helpers.EncryptionFileSet{Unencrypted: test.unencryptedFile, Encrypted: test.encryptedFile}
			hashes, err := calculateHashes(fileSet)

			assert.Equal(t, test.expectedError, err)

			if hashes != nil {
				assert.Equal(t, test.expectedUnencryptedMd5, hashes.unencryptedMd5)
				assert.Equal(t, test.expectedUnencryptedSha256, hashes.unencryptedSha256)
				assert.Equal(t, test.expectedEncryptedMd5, hashes.encryptedMd5)
				assert.Equal(t, test.expectedEncryptedSha256, hashes.encryptedSha256)

				return
			}

			assert.Equal(t, test.expectedUnencryptedMd5, "")
			assert.Equal(t, test.expectedUnencryptedSha256, "")
			assert.Equal(t, test.expectedEncryptedMd5, "")
			assert.Equal(t, test.expectedEncryptedSha256, "")
		})
	}
}
