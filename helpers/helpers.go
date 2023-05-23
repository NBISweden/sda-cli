package helpers

import (
	"encoding/xml"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/manifoldco/promptui"
	log "github.com/sirupsen/logrus"
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
	helpStart := lines[2]
	indent := strings.Index(helpStart, " ")
	format := "\n%s\n\n%" + fmt.Sprintf("%v", indent+1) + "s%s\n\n"

	return fmt.Sprintf(format, strings.Join(lines[2:], "\n"), " ", usage)
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

// Removes all positional arguments from os.Args, and returns them.
// This function assumes that all flags have exactly one value.
func getPositional() (positional []string) {
	i := 1
	for i < len(os.Args) {
		if os.Args[i][0] == '-' {
			// if the current arg is a flag, skip the flag and its value
			i += 2
		} else {
			// if the current arg is positional, remove it and add it to
			// `positional`
			positional = append(positional, os.Args[i])
			os.Args = append(os.Args[:i], os.Args[i+1:]...)
		}
	}

	return positional
}

func ParseArgs(args []string, argFlags *flag.FlagSet) error {
	var pos = getPositional()
	// append positional args back at the end of os.Args
	os.Args = append(os.Args, pos...)
	err := argFlags.Parse(args[1:])

	return err
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
