package helpers

import (
	"os"
	"path/filepath"

	log "github.com/sirupsen/logrus"
)

//
// Shared structs
//

// EncryptionFileSet is a struct type to keep track of infiles and outfiles for
// encryption and decryption
type EncryptionFileSet struct {
	Unencrypted string
	Encrypted   string
}

//
// Helper functions used by more than one module
//

// FileExists checks if a file exists in the file system. Note that this
// function will not check if the file is readable, or if the file is a
// directory, only if it exists.
func FileExists(filename string) bool {
	_, err := os.Stat(filename)

	return err == nil
}

// FileIsReadable checks that a file exists, and is readable by the program.
func FileIsReadable(filename string) bool {
	fileInfo, err := os.Stat(filename)
	if err != nil || fileInfo.IsDir() {
		return false
	}
	// Check readability by simply trying to open the file and read one byte
	inFile, err := os.Open(filepath.Clean(filename))
	if err != nil {
		return false
	}
	defer func() {
		if err := inFile.Close(); err != nil {
			log.Errorf("Error closing file: %s\n", err)
		}
	}()

	test := make([]byte, 1)
	_, err = inFile.Read(test)

	return err == nil
}
