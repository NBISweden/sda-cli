package list

import (
	"errors"
	"flag"
	"fmt"

	"github.com/NBISweden/sda-cli/upload"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/inhies/go-bytesize"
)

// Help text and command line flags.

// Usage text that will be displayed as command line help text when using the
// `help download` command
var Usage = `
USAGE: %s list -config <s3config-file> [prefix]

List: Lists recursively all files under the user's folder in the Sensitive Data Archive (SDA). 
      If the [prefix] parameter is used, only the files under the specified path will be returned.
`

// ArgHelp is the suffix text that will be displayed after the argument list in
// the module help
var ArgHelp = `
  [prefix]
        the location/folder of the s3 to list contents`

// Args is a flagset that needs to be exported so that it can be written to the
// main program help
var Args = flag.NewFlagSet("list", flag.ExitOnError)

var configPath = Args.String("config", "", "S3 config file to use for listing.")

func listFiles(config *upload.Config, prefix string) (result *s3.ListObjectsV2Output, err error) {
	sess := session.Must(session.NewSession(&aws.Config{
		// The region for the backend is always the specified one
		// and not present in the configuration from auth - hardcoded
		Region:           aws.String("us-west-2"),
		Credentials:      credentials.NewStaticCredentials(config.AccessKey, config.AccessKey, config.AccessToken),
		Endpoint:         aws.String(config.HostBase),
		DisableSSL:       aws.Bool(!config.UseHTTPS),
		S3ForcePathStyle: aws.Bool(true),
	}))

	svc := s3.New(sess)

	result, err = svc.ListObjectsV2(&s3.ListObjectsV2Input{
		Bucket: aws.String(config.AccessKey + "/"),
		Prefix: aws.String(config.AccessKey + "/" + prefix),
	})

	fmt.Println(result)
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case s3.ErrCodeNoSuchBucket:
				fmt.Println(s3.ErrCodeNoSuchBucket, aerr.Error())
			default:
				fmt.Println(aerr.Error())
			}
		} else {
			// Print the error, cast err to awserr.Error to get the Code and
			// Message from an error.
			fmt.Println(err.Error())
		}

		return nil, err
	}

	return result, nil
}

// List function lists the contents of an s3
func List(args []string) error {

	err := Args.Parse(args[1:])
	if err != nil {
		return fmt.Errorf("failed parsing arguments, reason: %v", err)
	}

	prefix := ""
	if len(Args.Args()) > 1 {
		return errors.New("failed to parse prefix, only one is allowed")
	} else if len(Args.Args()) == 1 {
		prefix = Args.Args()[0]
	}

	// Check that the s3 configuration file path exists
	if *configPath == "" {
		return errors.New("failed to find an s3 configuration file for listing data")
	}

	// Get the configuration in the struct
	config, err := upload.LoadConfigFile(*configPath)
	if err != nil {
		return err
	}

	expiring, err := upload.CheckTokenExpiration(config.AccessToken)
	if err != nil {
		return err
	}
	if expiring {
		fmt.Println("The provided token expires in less than 24 hours")
		fmt.Println("Consider renewing the token.")
	}
	result, err := listFiles(config, prefix)
	if err != nil {
		return err
	}

	for i := range result.Contents {
		fmt.Printf("%s \t %s \n", bytesize.New(float64((*result.Contents[i].Size))), *result.Contents[i].Key)
	}

	return nil
}
