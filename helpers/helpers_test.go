package helpers

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"runtime"
	"testing"

	"github.com/stretchr/testify/suite"
)

type HelperTests struct {
	suite.Suite
	tempDir  string
	testFile *os.File
}

func TestHelpersTestSuite(t *testing.T) {
	suite.Run(t, new(HelperTests))
}

func (suite *HelperTests) SetupTest() {

	var err error

	// Create a temporary directory for our files
	suite.tempDir, err = ioutil.TempDir(os.TempDir(), "sda-cli-test-")
	if err != nil {
		log.Fatal("Couldn't create temporary test directory", err)
	}

	// create an existing test file with some known content
	suite.testFile, err = ioutil.TempFile(suite.tempDir, "testfile-")
	if err != nil {
		log.Fatal("cannot create temporary public key file", err)
	}

	err = ioutil.WriteFile(suite.testFile.Name(), []byte("content"), 0600)
	if err != nil {
		log.Fatalf("failed to write to testfile: %s", err)
	}
}

func (suite *HelperTests) TearDownTest() {
	os.Remove(suite.testFile.Name())
	os.Remove(suite.tempDir)
}

func (suite *HelperTests) TestFileExists() {
	// file exists
	testExists := FileExists(suite.testFile.Name())
	suite.Equal(testExists, true)
	// file does not exists
	testMissing := FileExists("does-not-exist")
	suite.Equal(testMissing, false)
	// file is a directory
	testIsDir := FileExists(suite.tempDir)
	suite.Equal(testIsDir, true)
}

func (suite *HelperTests) TestFileIsReadable() {
	// file doesn't exist
	testMissing := FileIsReadable("does-not-exist")
	suite.Equal(testMissing, false)

	// file is a directory
	testIsDir := FileIsReadable(suite.tempDir)
	suite.Equal(testIsDir, false)

	// file can be read
	testFileOk := FileIsReadable(suite.testFile.Name())
	suite.Equal(testFileOk, true)

	// test file permissions. This doesn't work on windows, so we do an extra
	// check to see if this test makes sense.
	if runtime.GOOS != "windows" {
		err := os.Chmod(suite.testFile.Name(), 0000)
		if err != nil {
			log.Fatal("Couldn't set file permissions of test file")
		}
		// file permissions don't allow reading
		testDisallowed := FileIsReadable(suite.testFile.Name())
		suite.Equal(testDisallowed, false)

		// restore permissions
		err = os.Chmod(suite.testFile.Name(), 0600)
		if err != nil {
			log.Fatal("Couldn't restore file permissions of test file")
		}
	}
}

func (suite *HelperTests) TestFormatSubcommandUsage() {
	// check formatting of malformed usage strings without %s for os.Args[0]
	malformedNoFormatString := "USAGE: do that stuff"
	testMissingArgsFormat := FormatSubcommandUsage(malformedNoFormatString)
	suite.Equal(malformedNoFormatString, testMissingArgsFormat)

	// check formatting when the USAGE string is missing
	malformedNoUsage := `module: this module does all the fancies stuff,
								   and virtually none of the non-fancy stuff.
								   run with: %s module`
	testNoUsage := FormatSubcommandUsage(malformedNoUsage)
	suite.Equal(fmt.Sprintf(malformedNoUsage, os.Args[0]), testNoUsage)

	// check formatting when the usage string is correctly formatted

	correctUsage := `USAGE: %s module <args>

module: this module does all the fancies stuff,
        and virtually none of the non-fancy stuff.`

	correctFormat := fmt.Sprintf(`
module: this module does all the fancies stuff,
        and virtually none of the non-fancy stuff.

        USAGE: %s module <args>

`, os.Args[0])
	testCorrect := FormatSubcommandUsage(correctUsage)
	suite.Equal(correctFormat, testCorrect)

}
