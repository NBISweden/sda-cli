package helpers

import (
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/manifoldco/promptui"
	log "github.com/sirupsen/logrus"
	"github.com/vbauerster/mpb/v8"
)

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

// FormatSubcommandUsage moves the lines in the standard usage strings around so
// that the usage string is indented under the help text instead of above it.
func FormatSubcommandUsage(usageString string) string {

	// check that there's a formatting thing for os.Args[0]
	if !strings.Contains(usageString, "%s") && !strings.Contains(usageString, "%v") {
		return usageString
	}

	// format usage string with command name
	usageString = fmt.Sprintf(usageString, os.Args[0])

	// break string into lines
	lines := strings.Split(strings.TrimSpace(usageString), "\n")
	if len(lines) < 2 || !strings.HasPrefix(lines[0], "USAGE:") {
		// if we don't have enough data, just return the usage string as is
		return usageString
	}
	// reformat lines
	usage := lines[0]

	return fmt.Sprintf("\n%s\n\n    %s\n\n", strings.Join(lines[2:], "\n"), usage)
}

// PromptPassword creates a user prompt for inputting passwords, where all
// characters are masked with "*"
func PromptPassword(message string) (password string, err error) {
	prompt := promptui.Prompt{
		Label: message,
		Mask:  '*',
	}

	return prompt.Run()
}

// ParseS3ErrorResponse checks if reader stream is xml encoded and if yes unmarshals
// the xml response and returns it.
func ParseS3ErrorResponse(respBody io.Reader) (string, error) {

	respMsg, err := io.ReadAll(respBody)
	if err != nil {
		return "", fmt.Errorf("failed to read from response body, reason: %v", err)
	}

	if !strings.Contains(string(respMsg), `xml version`) {
		return "", fmt.Errorf("cannot parse response body, reason: not xml")
	}

	xmlErrorResponse := XMLerrorResponse{}
	err = xml.Unmarshal(respMsg, &xmlErrorResponse)
	if err != nil {
		return "", fmt.Errorf("failed to unmarshal xml response, reason: %v", err)
	}

	return fmt.Sprintf("%+v", xmlErrorResponse), nil
}

//
// shared structs
//

// struct type to keep track of infiles and outfiles for encryption and
// decryption
type EncryptionFileSet struct {
	Unencrypted string
	Encrypted   string
}

// struct type to unmarshall xml error response from s3 server
type XMLerrorResponse struct {
	Code     string `xml:"Code"`
	Message  string `xml:"Message"`
	Resource string `xml:"Resource"`
}

// progress bar definitions
// Produces a progress bar with decorators that can produce different styles
// Check https://github.com/vbauerster/mpb for more info and how to use it
type CustomReader struct {
	Fp      *os.File
	Size    int64
	Reads   int64
	Bar     *mpb.Bar
	SignMap map[int64]struct{}
	Mux     sync.Mutex
}

func (r *CustomReader) Read(p []byte) (int, error) {
	return r.Fp.Read(p)
}

func (r *CustomReader) ReadAt(p []byte, off int64) (int, error) {
	n, err := r.Fp.ReadAt(p, off)
	if err != nil {
		return n, err
	}

	r.Bar.SetTotal(r.Size, false)

	r.Mux.Lock()
	// Ignore the first signature call
	if _, ok := r.SignMap[off]; ok {
		r.Reads += int64(n)
		r.Bar.SetCurrent(r.Reads)
	} else {
		r.SignMap[off] = struct{}{}
	}
	r.Mux.Unlock()

	return n, err
}

func (r *CustomReader) Seek(offset int64, whence int) (int64, error) {
	return r.Fp.Seek(offset, whence)
}
