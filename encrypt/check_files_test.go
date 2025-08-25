package encrypt

import (
	"fmt"
	"os"
	"testing"

	"github.com/NBISweden/sda-cli/helpers"
	"github.com/stretchr/testify/assert"
)

func TestCheckFiles(t *testing.T) {
	tempDir := t.TempDir()
	// create an existing test file with some known content
	fileToCheck, err := os.CreateTemp(tempDir, "testfile-")
	if err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	if _, err := fileToCheck.Write([]byte("content")); err != nil {
		t.Fatalf("failed to write to test file: %v", err)
	}
	_ = fileToCheck.Close()

	// create an existing encrypted test file
	encryptedFile, err := os.CreateTemp(tempDir, "encrypted-input")
	if err != nil {
		t.Fatalf("failed to create encrypted input test file: %v", err)
	}

	if _, err := encryptedFile.Write([]byte("crypt4gh")); err != nil {
		t.Fatalf("failed to write to encrypted input test file: %v", err)
	}
	_ = encryptedFile.Close()

	for _, test := range []struct {
		testName                       string
		unencryptedFile, encryptedFile string
		expectedError                  error
	}{
		{
			testName:        "EncryptedNotExist",
			unencryptedFile: fileToCheck.Name(),
			encryptedFile:   "does-not-exist",
			expectedError:   nil,
		}, {
			testName:        "BothExist",
			unencryptedFile: fileToCheck.Name(),
			encryptedFile:   fileToCheck.Name(),
			expectedError:   fmt.Errorf("outfile %s already exists", fileToCheck.Name()),
		}, {
			testName:        "UnencryptedNotExist",
			unencryptedFile: "does-not-exist",
			encryptedFile:   fileToCheck.Name(),
			expectedError:   fmt.Errorf("cannot read input file does-not-exist"),
		}, {
			testName:        "EncryptedAsInput",
			unencryptedFile: encryptedFile.Name(),
			encryptedFile:   "does-not-exist",
			expectedError:   fmt.Errorf("input file %s is already encrypted(.c4gh)", encryptedFile.Name()),
		},
	} {
		t.Run(test.testName, func(t *testing.T) {
			fileSet := helpers.EncryptionFileSet{Unencrypted: test.unencryptedFile, Encrypted: test.encryptedFile}
			assert.Equal(t, test.expectedError, checkFiles([]helpers.EncryptionFileSet{fileSet}))
		})
	}
}
