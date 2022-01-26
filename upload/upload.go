package upload

import (
	"errors"
	"flag"
	"os"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
	log "github.com/sirupsen/logrus"
	"gopkg.in/ini.v1"
)

// Help text and command line flags.

var Usage = `
USAGE: %s upload -config <s3config-file> [file(s)]

Upload: Uploads files to the Sensitive Data Archive (SDA). All files to upload
		are required to be encrypted and have the .c4gh file extension.
`
var ArgHelp = `
  [file(s)]
        all flagless arguments will be used as filenames to upload.`

var Args = flag.NewFlagSet("upload", flag.ExitOnError)

var configPath = Args.String("config", "", "S3 config file to use for uploading.")

// Configuration struct for storing the s3cmd file values
type Config struct {
	AccessKey            string `ini:"access_key"`
	SecretKey            string `ini:"secret_key"`
	AccessToken          string `ini:"access_token"`
	HostBucket           string `ini:"host_bucket"`
	HostBase             string `ini:"host_base"`
	MultipartChunkSizeMb int64  `ini:"multipart_chunk_size_mb"`
	GuessMimeType        bool   `ini:"guess_mime_type"`
	Encoding             string `ini:"encoding"`
	CheckSslCertificate  bool   `ini:"check_ssl_certificate"`
	CheckSslHostname     bool   `ini:"check_ssl_hostname"`
	UseHTTPS             bool   `ini:"use_https"`
	SocketTimeout        int    `ini:"socket_timeout"`
	HumanReadableSizes   bool   `ini:"human_readable_sizes"`
}

// Load ini configuration file to the Config struct
func loadConfigFile(path string) (*Config, error) {

	config := &Config{}

	cfg, err := ini.Load(path)
	if err != nil {
		return config, err
	}

	if err := cfg.Section("").MapTo(config); err != nil {
		return nil, err
	}

	if config.AccessKey == "" || config.AccessToken == "" {
		return nil, errors.New("failed to find credentials in configuration file")
	}

	if config.HostBase == "" {
		return nil, errors.New("failed to find endpoint in configuration file")
	}

	if config.UseHTTPS {
		config.HostBase = "https://" + config.HostBase
	}

	if config.Encoding == "" {
		config.Encoding = "UTF-8"
	}

	// Where 15 is the default chunk size of the library
	if config.MultipartChunkSizeMb <= 15 {
		config.MultipartChunkSizeMb = 50
	}

	return config, nil
}

// Main upload function
func Upload(args []string) error {
	err := Args.Parse(os.Args[1:])
	if err != nil {
		return err
	}

	// Args() returns the non-flag arguments, which we assume are filenames.
	files := Args.Args()
	if len(files) == 0 {
		return errors.New("no files to upload")
	}

	// Check that we have a private key to decrypt with
	if *configPath == "" {
		return errors.New("failed to find an s3 configuration file for uploading data")
	}

	// Get the configuration in the struct
	config, err := loadConfigFile(*configPath)
	if err != nil {
		return err
	}

	// The session the S3 Uploader will use
	sess := session.Must(session.NewSession(&aws.Config{
		// The region for the backend is always the specified one
		// and not present in the configuration from auth - hardcoded
		Region:           aws.String("us-west-2"),
		Credentials:      credentials.NewStaticCredentials(config.AccessKey, config.AccessKey, config.AccessToken),
		Endpoint:         aws.String(config.HostBase),
		DisableSSL:       aws.Bool(config.UseHTTPS),
		S3ForcePathStyle: aws.Bool(true),
	}))

	// Create an uploader with the session and default options
	uploader := s3manager.NewUploader(sess)

	for _, filename := range files {

		log.Infof("Uploading %s with config %s", filename, *configPath)

		f, err := os.Open(filename)
		if err != nil {
			return err
		}

		// Upload the file to S3.
		result, err := uploader.Upload(&s3manager.UploadInput{
			Body:            f,
			Bucket:          aws.String(config.AccessKey),
			Key:             aws.String(filename),
			ContentEncoding: aws.String(config.Encoding),
		}, func(u *s3manager.Uploader) {
			u.PartSize = config.MultipartChunkSizeMb * 1024 * 1024
			// Delete parts of failed multipart, since we cannot currently continue them
			u.LeavePartsOnError = false
		})
		if err != nil {
			return err
		}
		log.Infof("file uploaded to %s", string(aws.StringValue(&result.Location)))
	}

	return nil
}
