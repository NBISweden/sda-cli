package upload

import (
	"flag"
	"os"
	"strings"

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
	CheckSslCertificate  bool   `ini:"check_ssl_certificate"`
	CheckSslHostname     bool   `ini:"check_ssl_hostname"`
	SocketTimeout        int    `ini:"socket_timeout"`
	Encoding             string `ini:"encoding"`
	Encrypt              bool   `ini:"encrypt"`
	HumanReadableSizes   bool   `ini:"human_readable_sizes"`
	MultipartChunkSizeMb int64  `ini:"multipart_chunk_size_mb"`
	HostBucket           string `ini:"host_bucket"`
	HostBase             string `ini:"host_base"`
	GuessMimeType        bool   `ini:"guess_mime_type"`
	UseHttps             bool   `ini:"use_https"`
}

// Load ini configuration file to the Config struct
func loadConfigFile(path string) (*Config, error) {

	config := &Config{}

	cfg, err := ini.Load(path)
	if err != nil {
		return config, nil
	}

	if err := cfg.Section("").MapTo(config); err != nil {
		return nil, err
	}

	return config, nil
}

// Main upload function
func Upload(args []string) {
	Args.Parse(os.Args[1:])

	// Args() returns the non-flag arguments, which we assume are filenames.
	files := Args.Args()

	// Check that we have a private key to decrypt with
	if *configPath == "" {
		log.Fatal("An s3config is required to upload data")
	}
	log.Infof("Uploading %s with config %s", files, *configPath)

	// Get the configuration in the struct
	config, err := loadConfigFile(*configPath)
	if err != nil {
		log.Errorf("Error getting s3cmd configuration, %v", err)
	}

	// The session the S3 Uploader will use
	sess := session.Must(session.NewSession(&aws.Config{
		Region:           aws.String("us-west-2"),
		Credentials:      credentials.NewStaticCredentials(config.AccessKey, config.SecretKey, config.AccessToken),
		Endpoint:         aws.String("https://" + config.HostBase),
		DisableSSL:       aws.Bool(strings.HasPrefix("https://"+config.HostBase, "http:")),
		S3ForcePathStyle: aws.Bool(true),
	}))

	// Create an uploader with the session and default options
	uploader := s3manager.NewUploader(sess)

	for _, filename := range files {

		f, err := os.Open(filename)
		if err != nil {
			log.Errorf("failed to open file %q, %v", filename, err)
		}

		// Upload the file to S3.
		result, err := uploader.Upload(&s3manager.UploadInput{
			Body:   f,
			Bucket: aws.String(config.AccessKey),
			Key:    aws.String(filename),
		}, func(u *s3manager.Uploader) {
			u.PartSize = config.MultipartChunkSizeMb * 1024 * 1024
			// Delete parts of failed multipart, since we cannot currently continue them
			u.LeavePartsOnError = true
		})
		if err != nil {
			log.Errorf("failed to upload file, %v", err)
		}
		log.Info("file uploaded to, %s", aws.StringValue(&result.Location))
	}
}
