package upload

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/NBISweden/sda-cli/encrypt"
	"github.com/NBISweden/sda-cli/helpers"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
	log "github.com/sirupsen/logrus"
	"github.com/vbauerster/mpb/v8"
	"github.com/vbauerster/mpb/v8/decor"
)

// Help text and command line flags.

// Usage text that will be displayed as command line help text when using the
// `help upload` command
var Usage = `
Usage: %s -config <config-file> upload [OPTIONS] [file(s) | folder(s)]

Upload files or directories to the Sensitive Data Archive (SDA). 

Important:
  - Files must be encrypted (Crypt4GH standard) unless the '-encrypt-with-key' flag is set.
  - When using the '-encrypt-with-key' flag, ensure that only unencrypted files are provided.
  - Use the '-force-unencrypted' flag with caution to upload unencrypted files explicitly.

Global options:
  -config <config-file>       	   Path to the configuration file. 

Options:
  -accessToken <access-token>      Access token for the SDA inbox service. This is optional 
                                   if already set in the config file or as the 'ACCESSTOKEN' 
                                   environment variable.
  -continue                        Skip already uploaded files and continue with uploading the rest.
                                   Useful for resuming an upload from a previous breakpoint.
  -encrypt-with-key <public-key-file>
                                   Encrypt files using the specified public key before upload. 
                                   The key file may contain multiple concatenated public keys. 
                                   Only unencrypted files should be provided when this flag is used.
  -force-overwrite                 Overwrite existing files in the target directory without confirmation.
  -force-unencrypted               Allow uploading unencrypted files (use with caution).
  -r                               Upload directories recursively. Without this flag, directories 
                                   will be skipped.
  -targetDir <upload-directory>    Specify the target directory for uploaded files or folders. 
                                   Defaults to the user's base directory if not set.

Arguments:
  [file(s) | folder(s)]            List of files or directories to upload. Directories are 
                                   skipped unless the '-r' flag is provided.`

// Args is a flagset that needs to be exported so that it can be written to the
// main program help
var Args = flag.NewFlagSet("upload", flag.ExitOnError)

var forceUnencrypted = Args.Bool("force-unencrypted", false, "Force uploading unencrypted files.")

var dirUpload = Args.Bool("r", false, "Upload directories recursively.")

var targetDir = Args.String("targetDir", "",
	"Upload files or folders into this directory.  If flag is omitted,\n"+
		"all data will be uploaded in the user's base directory.")

var forceOverwrite = Args.Bool("force-overwrite", false, "Force overwrite existing files.")

var continueUpload = Args.Bool("continue", false, "Skip existing files and continue with the rest.")

var pubKeyPath = Args.String("encrypt-with-key", "",
	"Public key file to use for encryption of files before upload.\n"+
		"The key file may optionally contain several concatenated public keys.\n"+
		"Only unencrypted data should be provided when this flag is set.",
)

var accessToken = Args.String("accessToken", "", "Access token to the inbox service.\n(optional, if it is set in the config file or exported as the ENV `ACCESSTOKEN`)")

// Function uploadFiles uploads the files in the input list to the s3 bucket
func uploadFiles(files, outFiles []string, targetDir string, config *helpers.Config) error {
	// check also here in case sth went wrong with input files
	if len(files) == 0 {
		return errors.New("no files to upload")
	}

	// Loop through the list of file paths and check if their names are valid
	for _, filename := range outFiles {
		err := helpers.CheckValidChars(filename)
		if err != nil {
			return err
		}
	}

	// Loop through the list of files and check if they are encrypted
	// If we run into an unencrypted file and the flag force-unencrypted is not set, we stop the upload
	for _, filename := range files {
		f, err := os.Open(path.Clean(filename))
		if err != nil {
			return err
		}
		// Check if the file is encrypted and warn if not
		// Extracting the first 8 bytes of the header - crypt4gh
		magicWord := make([]byte, 8)
		_, err = f.Read(magicWord)
		if err != nil {
			fmt.Printf("error reading input file %s, reason: %v", filename, err)
		}
		if string(magicWord) != "crypt4gh" {
			fmt.Printf("Input file %s is not encrypted\n", filename)
			log.Infof("input file %s is not encrypted", filepath.Clean(filename))
			if !*forceUnencrypted {
				fmt.Println("Quitting...")

				return errors.New("unencrypted file found")
			}
			fmt.Println("force-unencrypted flag provided, continuing...")
		}
	}

	// The session the S3 Uploader will use
	sess := session.Must(session.NewSession(&aws.Config{
		// The region for the backend is always the specified one
		// and not present in the configuration from auth - hardcoded
		Region: aws.String("us-west-2"),
		Credentials: credentials.NewStaticCredentials(
			config.AccessKey,
			config.SecretKey,
			config.AccessToken,
		),
		Endpoint:         aws.String(config.HostBase),
		DisableSSL:       aws.Bool(!config.UseHTTPS),
		S3ForcePathStyle: aws.Bool(true),
	}))
	// Create an uploader with the session and default options
	uploader := s3manager.NewUploader(sess)
	for k, filename := range files {

		// create progress bar instance
		p := mpb.New()

		f, err := os.Open(path.Clean(filename))
		if err != nil {
			return err
		}

		if *forceOverwrite {
			fmt.Println("force-overwrite flag provided, continuing by overwritting target...")
		} else {
			// Check if files exists in S3
			listPrefix := outFiles[k]
			if targetDir != "" {
				listPrefix = targetDir + "/" + outFiles[k]
			}

			listResult, err := helpers.ListFiles(*config, listPrefix)
			if err != nil {
				return fmt.Errorf("listing uploaded files: %s", err.Error())
			}

			fileExists := len(listResult) > 0 && aws.StringValue(listResult[0].Key) == filepath.Clean(config.AccessKey+"/"+listPrefix)
			switch {
			case fileExists && *continueUpload:
				fmt.Printf("File %s has already been uploaded, continuing with the next file...\n", filepath.Base(filename))

				continue
			case fileExists && !*continueUpload:
				return fmt.Errorf("file %s is already uploaded", filepath.Base(filename))
			}
		}

		fileInfo, err := f.Stat()
		if err != nil {
			return err
		}
		file := fmt.Sprintf("File %s:", filepath.Base(filename))
		// Creates a custom reader. The progress bar starts with the file name,
		// followed by the uploading status and the progress bar itself.
		// It is marked as done when the upload is complete
		reader := helpers.CustomReader{
			Fp:      f,
			Size:    fileInfo.Size(),
			SignMap: map[int64]struct{}{},
			Bar: p.AddBar(fileInfo.Size(),
				mpb.PrependDecorators(
					decor.Name(file, decor.WC{W: len(file) + 1, C: decor.DindentRight}),
					decor.Name("uploading", decor.WCSyncSpaceR),
					decor.Counters(decor.SizeB1024(0), "% .1f / % .1f"),
				),
				mpb.AppendDecorators(
					decor.OnComplete(decor.Percentage(decor.WC{W: 5}), "done"),
				),
			),
		}

		// Upload the file to S3.
		result, err := uploader.Upload(&s3manager.UploadInput{
			Body:            &reader,
			Bucket:          aws.String(config.AccessKey),
			Key:             aws.String(targetDir + "/" + outFiles[k]),
			ContentEncoding: aws.String(config.Encoding),
		}, func(u *s3manager.Uploader) {
			u.PartSize = config.MultipartChunkSizeMb * 1024 * 1024
			// Delete parts of failed multipart, since we cannot currently continue them
			u.LeavePartsOnError = false
		})
		// Print the progress bar. Second check is to filter out some junk from the output
		if result != nil && result.VersionID != nil {
			fmt.Println(result)
		}
		if err != nil {
			return err
		}
		log.Infof("file uploaded to %s\n", string(aws.StringValue(&result.Location)))
		p.Shutdown()
	}

	return nil
}

// Function createFilePaths returns a slice with all absolute paths to files within a directory recursively
// and a slice with the corresponding relative paths to the given directory
func createFilePaths(dirPath string) ([]string, []string, error) {
	var files []string
	var outFiles []string

	// Restrict function to work only with directories so that outFiles works as expected
	fileInfo, err := os.Stat(dirPath)
	if err != nil {
		return nil, nil, err
	}
	if !fileInfo.IsDir() {
		return nil, nil, errors.New(dirPath + " is not a directory")
	}

	// List all directory contents recursively including relative paths
	err = filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			fmt.Println(err)

			return err
		}
		// Exclude folders
		if !info.IsDir() {
			// Write relative file paths in a list
			files = append(files, path)

			// Create and write upload paths in a list
			// Remove possible trailing "/" so that "path" and "path/" behave the same
			dirPath = strings.TrimSuffix(dirPath, string(os.PathSeparator))
			pathToTrim := strings.TrimSuffix(dirPath, filepath.Base(dirPath))
			outPath := filepath.ToSlash(strings.TrimPrefix(path, pathToTrim))
			outFiles = append(outFiles, outPath)
		}

		return nil
	})
	if err != nil {
		return nil, nil, err
	}

	return files, outFiles, nil
}

// Upload function uploads files to the s3 bucket. Input can be files or
// directories to be uploaded recursively
func Upload(args []string, configPath string) error {
	var files []string
	var outFiles []string
	*pubKeyPath = ""
	*targetDir = ""

	// Call ParseArgs to take care of all the flag parsing
	err := helpers.ParseArgs(args, Args)
	if err != nil {
		return fmt.Errorf("failed parsing arguments, reason: %v", err)
	}

	// Dereference the pointer to a string
	var targetDirString string
	if targetDir != nil {
		targetDirString = *targetDir
	}

	err = helpers.CheckValidChars(filepath.ToSlash(targetDirString))
	if err != nil {
		return errors.New(*targetDir + " is not a valid target directory")
	}

	// Check that specified target directory is valid, i.e. not a filepath or a flag
	info, err := os.Stat(*targetDir)

	if (!os.IsNotExist(err) && !info.IsDir()) ||
		(targetDirString != "" && targetDirString[0:1] == "-") {
		return errors.New(*targetDir + " is not a valid target directory")
	}

	// Get the configuration file or the .sda-cli-session
	config, err := helpers.GetAuth(configPath)
	if err != nil {
		return err
	}

	switch {
	case os.Getenv("ACCESSTOKEN") == "" && *accessToken == "" && config.AccessToken == "":
		return errors.New("no access token supplied")
	case os.Getenv("ACCESSTOKEN") != "" && *accessToken == "":
		config.AccessToken = os.Getenv("ACCESSTOKEN")
	case *accessToken != "":
		config.AccessToken = *accessToken
	}

	err = helpers.CheckTokenExpiration(config.AccessToken)
	if err != nil {
		return err
	}

	// Check that input file/folder list is not empty
	if len(Args.Args()) == 0 {
		return errors.New("no files to upload")
	}

	// Check if input argument is a file or directory and
	// populate file list for upload
	for _, filePath := range Args.Args() {
		fileInfo, err := os.Stat(filePath)
		if err != nil {
			return err
		}
		if fileInfo.IsDir() {
			if !*dirUpload {
				fmt.Println(errors.New("-r not specified; omitting directory: " + filePath))

				continue
			}
			dirFilePaths, upFilePaths, err := createFilePaths(filePath)
			if err != nil {
				return err
			}

			if len(dirFilePaths) == 0 {
				fmt.Printf("Omitting directory: %s because it is empty\n", filePath)

				continue
			}

			files = append(files, dirFilePaths...)
			outFiles = append(outFiles, upFilePaths...)
		} else {
			files = append(files, filePath)
			outFiles = append(outFiles, filepath.ToSlash(filepath.Base(filePath)))
		}
	}

	// If files list is empty fail here before calling Encrypt
	if len(files) == 0 {
		return errors.New("no files to upload")
	}

	if *pubKeyPath != "" {
		// Prepare input arg list for Encrypt function
		encryptArgs := []string{args[0], "-key", *pubKeyPath}
		encryptArgs = append(encryptArgs, files...)

		if err = encrypt.Encrypt(encryptArgs); err != nil {
			return err
		}

		// Modify slices so that we upload only the encrypted files
		for k := 0; k < len(files); k++ {
			files[k] += ".c4gh"
			outFiles[k] += ".c4gh"
		}
	}

	return uploadFiles(files, outFiles, filepath.ToSlash(*targetDir), config)
}
