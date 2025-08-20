package decrypt

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	createKey "github.com/NBISweden/sda-cli/create_key"
	"github.com/stretchr/testify/assert"
)

func TestReadPrivateKeyFile(t *testing.T) {
	tempDir := t.TempDir()

	testFile, err := os.CreateTemp(tempDir, "testfile-")
	if err != nil {
		t.Fatal(err)
	}

	testKeyFile := filepath.Join(tempDir, "testkey")
	// generate key files
	err = createKey.GenerateKeyPair(testKeyFile, "test")
	if err != nil {
		t.Fatal(err)
	}

	_ = testFile.Close()

	for _, test := range []struct {
		testName         string
		fileName         string
		password         string
		expectedErrorMsg error
	}{
		{
			testName:         "FileNotExists",
			fileName:         testKeyFile,
			password:         "Doesnt matter",
			expectedErrorMsg: fmt.Errorf("private key file %s doesn't exist", testKeyFile),
		},
		{
			testName:         "NotAKeyFile",
			fileName:         testFile.Name(),
			password:         "Doesnt matter",
			expectedErrorMsg: fmt.Errorf("read of unrecognized private key format failed; expected PEM encoded key, file: %s", testFile.Name()),
		},
		{
			testName:         "ReadPublicKey",
			fileName:         fmt.Sprintf("%s.pub.pem", testKeyFile),
			password:         "Doesnt matter",
			expectedErrorMsg: fmt.Errorf("private key format not supported, file: %s", fmt.Sprintf("%s.pub.pem", testKeyFile)),
		},
		{
			testName:         "WrongPassword",
			fileName:         fmt.Sprintf("%s.sec.pem", testKeyFile),
			password:         "wrong",
			expectedErrorMsg: fmt.Errorf("chacha20poly1305: message authentication failed, file: %s", fmt.Sprintf("%s.sec.pem", testKeyFile)),
		},
		{
			testName:         "Successful",
			fileName:         fmt.Sprintf("%s.sec.pem", testKeyFile),
			password:         "test",
			expectedErrorMsg: nil,
		},
	} {
		t.Run(test.testName, func(t *testing.T) {
			_, err = readPrivateKeyFile(test.fileName, test.password)
			assert.Equal(t, err, test.expectedErrorMsg)
		})
	}
}
