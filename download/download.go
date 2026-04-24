package download

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/NBISweden/sda-cli/apiclient"
	rootcmd "github.com/NBISweden/sda-cli/cmd"
	"github.com/NBISweden/sda-cli/helpers"
	"github.com/spf13/cobra"
	"github.com/vbauerster/mpb/v8"
	"github.com/vbauerster/mpb/v8/decor"
)

var datasetID string
var URL string
var ignoreExisting bool
var overwriteExisting bool
var outDir string
var datasetDownload bool
var pubKey string
var recursiveDownload bool
var fromFile bool
var pubKeyBase64 string
var apiVersionFlag string

var downloadCmd = &cobra.Command{
	Use:   "download [flags] [filepath(s) | fileid(s)]",
	Short: "Download files from SDA",
	Long: `Download files from the Sensitive Data Archive (SDA) using APIs at the specified URL.
	The user must have the necessary access rights (visas) to the datasets being downloaded
	Important:
		Provide exactly one of the following options to specify files to download:
			- [filepath(s) or fileid(s)]
			- --dataset
			- --recursive <dirpath>
			- --from-file <list-filepath>`,
	RunE: func(cmd *cobra.Command, args []string) error {
		configPath := cmd.Root().Flag("config").Value.String()
		err := Download(args, configPath, rootcmd.Version)
		if err != nil {
			return err
		}

		return nil
	},
}

func init() {
	rootcmd.AddCommand(downloadCmd)
	downloadCmd.Flags().StringVar(&datasetID, "dataset-id", "", "Dataset ID for the file(s) to download")
	downloadCmd.Flags().StringVar(&URL, "url", "", "The url of the download server")
	downloadCmd.Flags().BoolVar(&ignoreExisting, "ignore-existing", false, "Skip existing files and continue with the rest")
	downloadCmd.Flags().BoolVar(&overwriteExisting, "overwrite-existing", false, "Overwrite existing files")
	downloadCmd.Flags().StringVar(&outDir, "outdir", "", "Directory to output downloaded files")
	downloadCmd.Flags().BoolVar(&datasetDownload, "dataset", false, "Download all the files of the dataset")
	downloadCmd.Flags().StringVar(&pubKey, "pubkey", "", "Path to the public key file to use for encryption of files to download")
	downloadCmd.Flags().BoolVarP(&recursiveDownload, "recursive", "r", false, "Download all content from a folder recursively")
	downloadCmd.Flags().BoolVar(&fromFile, "from-file", false, "Download files from file list")
	downloadCmd.Flags().StringVar(&apiVersionFlag, "api-version", "v1", "SDA download API version to use (v1 or v2)")
}

// Download function downloads files from the SDA by using the
// download's service APIs
func Download(args []string, configPath, version string) error {
	if datasetID == "" || URL == "" || configPath == "" {
		return errors.New("missing required arguments, dataset-id, config and url are required")
	}

	// Check if both --ignore-existing and --overwrite-existing are set
	if ignoreExisting && overwriteExisting {
		return errors.New("both --ignore-existing and --overwrite-existing flags are set, choose one of them")
	}

	// Check if both --recursive and --dataset flags are set
	if recursiveDownload && datasetDownload {
		return errors.New("both --recursive and --dataset flags are set, choose one of them")
	}

	// Check that file(s) are not missing if the --dataset flag is not set
	if len(args) == 0 && !datasetDownload {
		if !recursiveDownload {
			return errors.New("no files provided for download")
		}

		return errors.New("no folders provided for recursive download")
	}

	if datasetDownload && len(args) > 0 {
		return errors.New("files provided with --dataset flag, add either the flag or the file(s), not both")
	}

	if fromFile && len(args) != 1 {
		return errors.New("one file should be provided with the --from-file flag")
	}

	config, err := helpers.GetAuth(configPath)
	if err != nil {
		return err
	}

	err = helpers.CheckTokenExpiration(config.AccessToken)
	if err != nil {
		return err
	}

	pubKeyBase64, err = helpers.GetPublicKey64(&pubKey)
	if err != nil {
		return err
	}

	client, err := apiclient.New(apiclient.Config{
		BaseURL: URL,
		Token:   config.AccessToken,
		Version: version,
	}, apiVersionFlag)
	if err != nil {
		return err
	}
	ctx := context.Background()

	helpers.PrintHostBase(config.HostBase)

	switch {
	case datasetDownload:
		err = datasetCase(ctx, client)
		if err != nil {
			return err
		}
	case recursiveDownload:
		err = recursiveCase(ctx, client, args)
		if err != nil {
			return err
		}
	case fromFile:
		err = fileCase(ctx, client, args, true)
		if err != nil {
			return err
		}
	default:
		err = fileCase(ctx, client, args, false)
		if err != nil {
			return err
		}
	}

	return nil
}

func datasetCase(ctx context.Context, client apiclient.Client) error {
	fmt.Println("Downloading all files in the dataset")
	files, err := client.ListFiles(ctx, datasetID, apiclient.ListFilesOptions{})
	if err != nil {
		return fmt.Errorf("failed to get files, reason: %v", err)
	}

	for _, file := range files {
		if err := downloadOne(ctx, client, file.FilePath); err != nil {
			return err
		}
	}

	return nil
}

func recursiveCase(ctx context.Context, client apiclient.Client, args []string) error {
	fmt.Println("Downloading content of the path(s)")

	var dirPaths []string
	for _, path := range args {
		if !strings.HasSuffix(path, "/") {
			path += "/"
		}
		dirPaths = append(dirPaths, path)
	}

	// v1 has no server-side prefix filter, so fetch the full list once and
	// filter client-side. v2 has a pathPrefix filter; apply it per dirPath.
	var allFiles []apiclient.File
	if apiVersionFlag != "v2" {
		files, err := client.ListFiles(ctx, datasetID, apiclient.ListFilesOptions{})
		if err != nil {
			return fmt.Errorf("failed to get files, reason: %v", err)
		}
		allFiles = files
	}

	var missingPaths []string
	for _, dirPath := range dirPaths {
		var matched []apiclient.File
		if apiVersionFlag == "v2" {
			files, err := client.ListFiles(ctx, datasetID, apiclient.ListFilesOptions{PathPrefix: dirPath})
			if err != nil {
				return fmt.Errorf("failed to get files, reason: %v", err)
			}
			matched = files
		} else {
			for _, f := range allFiles {
				if strings.HasPrefix(f.FilePath, dirPath) {
					matched = append(matched, f)
				}
			}
		}

		if len(matched) == 0 {
			missingPaths = append(missingPaths, dirPath)

			continue
		}
		for _, file := range matched {
			if err := downloadOne(ctx, client, file.FilePath); err != nil {
				return err
			}
		}
	}
	if len(missingPaths) == len(dirPaths) {
		return errors.New("given path(s) do not exist")
	}
	if len(missingPaths) > 0 {
		for _, missingPath := range missingPaths {
			fmt.Println("Non existing path: ", missingPath)
		}
	}

	return nil
}

func fileCase(ctx context.Context, client apiclient.Client, args []string, fileList bool) error {
	var files []string
	if fileList {
		fmt.Println("Downloading files from file list")
		fl, err := GetURLsFile(args[0])
		if err != nil {
			return err
		}
		files = append(files, fl...)
	} else {
		fmt.Println("Downloading files")
		files = append(files, args...)
	}

	for _, filePath := range files {
		if err := downloadOne(ctx, client, filePath); err != nil {
			return err
		}
	}

	return nil
}

// downloadOne fetches a single file via the apiclient.Client and writes it
// to disk under outDir. userArg is either a path or a fileId — the client's
// DownloadFile resolves it and returns the canonical File, which we use for
// the on-disk name (UserArg must not be used for the filename because it
// may be a bare fileId with no relationship to the actual file name).
func downloadOne(ctx context.Context, client apiclient.Client, userArg string) error {
	result, err := client.DownloadFile(ctx, apiclient.DownloadRequest{
		DatasetID:       datasetID,
		UserArg:         userArg,
		PublicKeyBase64: pubKeyBase64,
	})
	if err != nil {
		return err
	}
	defer result.Body.Close() //nolint:errcheck

	// Server-provided metadata must not be able to escape the configured
	// output directory via "../" segments or absolute paths. filepath.IsLocal
	// is the safety boundary: it rejects "..", absolute paths, and (on
	// Windows) reserved names. This works correctly even when outDir is
	// empty (default) or ".", cases the previous prefix-check rejected.
	anonymized := helpers.AnonymizeFilepath(result.File.FilePath)
	if !filepath.IsLocal(anonymized) {
		return fmt.Errorf("refusing to write outside outdir: %s", result.File.FilePath)
	}
	od := outDir
	if od == "" {
		od = "."
	}
	outputPath := filepath.Join(od, anonymized)

	// Clean up any stale .part from a previous failed run before the
	// existing-file check — otherwise a prior .part could be left behind
	// when we end up skipping due to ignore-existing.
	partPath := outputPath + ".part"
	if _, serr := os.Stat(partPath); serr == nil {
		if rerr := os.Remove(partPath); rerr != nil {
			fmt.Printf("Warning: could not remove old partial file %s: %v\n", partPath, rerr)
		}
	}

	exists, err := handleExistingFile(outputPath)
	if err != nil {
		return err
	}
	if exists {
		return nil
	}

	return writeBodyToDisk(result.Body, result.ContentLength, outputPath)
}

// writeBodyToDisk streams the encrypted response body to destPath, driving
// an mpb progress bar sized by totalSize (0 = indeterminate spinner). Writes
// to destPath + ".part" first and renames on success; cleans up the .part
// on failure.
func writeBodyToDisk(body io.Reader, totalSize int64, destPath string) error {
	if err := os.MkdirAll(filepath.Dir(destPath), 0750); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	outFile, err := os.Create(destPath + ".part")
	if err != nil {
		return fmt.Errorf("failed to create partial file: %w", err)
	}

	var downloadSuccessful bool
	defer func() {
		_ = outFile.Close()
		if !downloadSuccessful {
			_ = os.Remove(outFile.Name()) // #nosec G703
		}
	}()

	buf := make([]byte, 1024*1024)
	bufReader := bufio.NewReaderSize(body, 1024*1024)

	p := mpb.New(
		mpb.WithRefreshRate(150 * time.Millisecond),
	)

	fmt.Printf("Downloading file to %s\n", destPath)

	if totalSize > 0 {
		if err := downloadWithBar(p, outFile, bufReader, totalSize, buf); err != nil {
			return err
		}
	} else {
		if err := downloadStreaming(p, outFile, bufReader, buf); err != nil {
			return err
		}
	}

	p.Wait()

	// This is critical for Windows compatibility
	if err := outFile.Close(); err != nil {
		return fmt.Errorf("failed to close partial file %s: %v", outFile.Name(), err)
	}

	if err := os.Rename(outFile.Name(), destPath); err != nil { // #nosec G703
		return fmt.Errorf("failed to rename partial file %s: %v", outFile.Name(), err)
	}

	downloadSuccessful = true

	return nil
}

func handleExistingFile(filePath string) (bool, error) {
	if _, err := os.Stat(filePath); errors.Is(err, os.ErrNotExist) {
		return false, nil
	}

	if ignoreExisting {
		fmt.Printf("Skipping download to %s, file already exists\n", filePath)

		return true, nil
	}

	if !overwriteExisting {
		choice, err := helpers.PromptOverwrite(filePath)
		if err != nil {
			return false, fmt.Errorf("failed to prompt for overwrite: %w", err)
		}

		switch choice {
		case helpers.OverwriteAlways:
			overwriteExisting = true
		case helpers.OverwriteYes:
			// Proceed to remove and download
		case helpers.OverwriteNever:
			ignoreExisting = true

			fallthrough
		case helpers.OverwriteNo:
			fmt.Printf("Skipping download to %s, file already exists\n", filePath)

			return true, nil
		default:
			return false, fmt.Errorf("unknown overwrite choice: %v", choice)
		}
	}

	if err := os.Remove(filePath); err != nil {
		return false, fmt.Errorf("failed to remove existing file: %w", err)
	}

	return false, nil
}

func GetURLsFile(urlsFilePath string) (urlsList []string, err error) {
	urlsFile, err := os.Open(filepath.Clean(urlsFilePath))
	if err != nil {
		return nil, err
	}
	defer urlsFile.Close() //nolint:errcheck

	scanner := bufio.NewScanner(urlsFile)
	for scanner.Scan() {
		urlsList = append(urlsList, scanner.Text())
	}
	if len(urlsList) == 0 {
		return urlsList, errors.New("failed to get list of files, empty file")
	}

	return urlsList, scanner.Err()
}

func downloadWithBar(p *mpb.Progress, outFile *os.File, reader io.Reader, totalSize int64, buf []byte) error {
	bar := p.AddBar(totalSize,
		mpb.PrependDecorators(
			decor.CountersKibiByte("% .2f / % .2f"),
		),
		mpb.AppendDecorators(
			decor.Percentage(),
		),
	)

	proxyReader := bar.ProxyReader(reader)
	if _, err := io.CopyBuffer(outFile, proxyReader, buf); err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}

	return nil
}

func downloadStreaming(p *mpb.Progress, outFile *os.File, reader *bufio.Reader, buf []byte) error {
	bar := p.New(
		0,
		mpb.SpinnerStyle("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"),
		mpb.PrependDecorators(
			decor.CurrentKibiByte("% .2f"),
		),
		mpb.AppendDecorators(
			decor.Name(" downloading..."),
		),
	)
	defer bar.Abort(true)

	for {
		n, err := reader.Read(buf)
		if n > 0 {
			if _, werr := outFile.Write(buf[:n]); werr != nil {
				return werr
			}
			bar.IncrBy(n)
		}

		if err != nil {
			if err == io.EOF {
				break
			}

			return err
		}
	}

	return nil
}
