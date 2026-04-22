package download

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/NBISweden/sda-cli/apiclient"
	rootcmd "github.com/NBISweden/sda-cli/cmd"
	"github.com/NBISweden/sda-cli/helpers"
	"github.com/spf13/cobra"
	"github.com/vbauerster/mpb/v8"
	"github.com/vbauerster/mpb/v8/decor"
	"go.nhat.io/cookiejar"
	"golang.org/x/net/publicsuffix"
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

var cookieJar *cookiejar.PersistentJar
var cookiePath string
var appVersion string

// File is the file metadata type. Canonical definition lives in apiclient.
// Alias preserves source compat for existing callers (list/, tests). Removed
// in #677 when callers reference apiclient.File directly.
type File = apiclient.File

// Download function downloads files from the SDA by using the
// download's service APIs
func Download(args []string, configPath, version string) error {
	appVersion = version

	if datasetID == "" || URL == "" || configPath == "" {
		return errors.New("missing required arguments, dataset-id, config and url are required")
	}

	// Fail fast on an unsupported --api-version before we touch the
	// filesystem via setupCookieJar. Cheap check; avoids creating
	// ${UserCacheDir}/sda-cli/ when the command is about to error out.
	if err := apiclient.ValidateVersion(apiVersionFlag); err != nil {
		return err
	}

	u, err := url.Parse(URL)
	if err != nil || u.Scheme == "" {
		return errors.New("invalid base URL")
	}
	setupCookieJar(u)

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

	// Share the cookie jar that downloadFile uses so V1Client's metadata
	// calls and the legacy /s3 transfer path see the same in-memory
	// cookie state. Two independent AutoSync:ed jars on the same on-disk
	// file would race and clobber each other (fixed here; removed in
	// #677 when downloadFile also moves onto apiclient.Client).
	client, err := apiclient.New(apiclient.Config{
		BaseURL: URL,
		Token:   config.AccessToken,
		Version: version,
	}, apiVersionFlag, apiclient.WithV1CookieJar(cookieJar))
	if err != nil {
		return err
	}
	ctx := context.Background()

	helpers.PrintHostBase(config.HostBase)

	switch {
	case datasetDownload:
		err = datasetCase(ctx, client, config.AccessToken)
		if err != nil {
			return err
		}
	case recursiveDownload:
		err = recursiveCase(ctx, client, args, config.AccessToken)
		if err != nil {
			return err
		}
	case fromFile:
		err = fileCase(ctx, client, args, config.AccessToken, true)
		if err != nil {
			return err
		}
	default:
		err = fileCase(ctx, client, args, config.AccessToken, false)
		if err != nil {
			return err
		}
	}

	return nil
}

func datasetCase(ctx context.Context, client apiclient.Client, token string) error {
	fmt.Println("Downloading all files in the dataset")
	files, err := client.ListFiles(ctx, datasetID, apiclient.ListFilesOptions{})
	if err != nil {
		return fmt.Errorf("failed to get files, reason: %v", err)
	}

	for _, file := range files {
		fileName := helpers.AnonymizeFilepath(file.FilePath)
		fileURL := URL + "/s3/" + datasetID + "/" + fileName

		err = downloadFile(fileURL, token, pubKeyBase64, file.FilePath)
		if err != nil {
			return err
		}
	}

	return nil
}

func recursiveCase(ctx context.Context, client apiclient.Client, args []string, token string) error {
	fmt.Println("Downloading content of the path(s)")
	files, err := client.ListFiles(ctx, datasetID, apiclient.ListFilesOptions{})
	if err != nil {
		return fmt.Errorf("failed to get files, reason: %v", err)
	}

	var dirPaths []string
	for _, path := range args {
		if !strings.HasSuffix(path, "/") {
			path += "/"
		}
		dirPaths = append(dirPaths, path)
	}
	var missingPaths []string
	// Loop over all the files of the dataset and
	// check if the provided path is part of their filepath.
	// If it is then download the file
	for _, dirPath := range dirPaths {
		pathExists := false
		for _, file := range files {
			if strings.HasPrefix(file.FilePath, dirPath) {
				pathExists = true
				fileName := helpers.AnonymizeFilepath(file.FilePath)
				fileURL := URL + "/s3/" + datasetID + "/" + fileName
				err = downloadFile(fileURL, token, pubKeyBase64, file.FilePath)
				if err != nil {
					return err
				}
			}
		}
		if !pathExists {
			missingPaths = append(missingPaths, dirPath)
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

func fileCase(ctx context.Context, client apiclient.Client, args []string, token string, fileList bool) error {
	var files []string
	if fileList {
		fmt.Println("Downloading files from file list")
		fileList, err := GetURLsFile(args[0])
		if err != nil {
			return err
		}
		files = append(files, fileList...)
	} else {
		fmt.Println("Downloading files")
		files = append(files, args...)
	}

	for _, filePath := range files {
		outputPath := filepath.Join(outDir, filePath)
		// Cleanup .part if it exists since we are skipping
		partPath := outputPath + ".part"
		if _, err := os.Stat(partPath); err == nil {
			if err := os.Remove(partPath); err != nil {
				fmt.Printf("Warning: could not remove old partial file %s: %v\n", partPath, err)
			}
		}

		if ignoreExisting {
			if _, err := os.Stat(outputPath); err == nil {
				fmt.Printf("Skipping download to %s, file already exists\n", outputPath)

				continue
			} else if !errors.Is(err, os.ErrNotExist) {
				return err
			}
		}

		fileIDURL, apiFilePath, err := getFileIDURL(ctx, client, URL, datasetID, pubKeyBase64, filePath)
		if err != nil {
			return err
		}

		err = downloadFile(fileIDURL, token, pubKeyBase64, apiFilePath)
		if err != nil {
			return err
		}
	}

	return nil
}

func downloadFile(uri, token, pubKeyBase64, filePath string) error {
	filePath = helpers.AnonymizeFilepath(filePath)
	filePath = filepath.Join(outDir, filePath)

	exists, err := handleExistingFile(filePath)
	if err != nil {
		return err
	}
	if exists {
		return nil
	}

	bodyStream, totalSize, err := getBody(uri, token, pubKeyBase64)
	if err != nil {
		return err
	}
	defer bodyStream.Close()

	if err := os.MkdirAll(filepath.Dir(filePath), 0750); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	outFile, err := os.Create(filePath + ".part")
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
	bufReader := bufio.NewReaderSize(bodyStream, 1024*1024)

	p := mpb.New(
		mpb.WithRefreshRate(150 * time.Millisecond),
	)

	fmt.Printf("Downloading file to %s\n", filePath)

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

	if err := os.Rename(outFile.Name(), filePath); err != nil { // #nosec G703
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

func getFileIDURL(ctx context.Context, client apiclient.Client, baseURL, dataset, pubKeyBase64, filename string) (string, string, error) {
	// Preserve legacy behavior: if baseURL is invalid, return "invalid base URL"
	// without wrapping (TestFileIdUrl/InvalidUrl asserts on the bare string).
	u, err := url.ParseRequestURI(baseURL)
	if err != nil || u.Scheme == "" {
		return "", "", errors.New("invalid base URL")
	}

	// Forward the caller's pubkey on v1 so the Client-Public-Key header is
	// emitted on /files listing — matches the original download.getFileIDURL →
	// GetFilesInfo → getBody wire behavior. V2 ignores LegacyV1PubKey.
	datasetFiles, err := client.ListFiles(ctx, dataset, apiclient.ListFilesOptions{
		LegacyV1PubKey: pubKeyBase64,
	})
	if err != nil {
		return "", "", fmt.Errorf("failed to get files, reason: %v", err)
	}

	var idx int
	switch {
	case strings.Contains(filename, "/"):
		if !strings.HasSuffix(filename, ".c4gh") {
			filename += ".c4gh"
		}
		idx = slices.IndexFunc(
			datasetFiles,
			func(f File) bool { return strings.Contains(f.FilePath, filename) },
		)
	default:
		idx = slices.IndexFunc(
			datasetFiles,
			func(f File) bool { return strings.Contains(f.FileID, filename) },
		)
	}

	if idx == -1 {
		return "", "", fmt.Errorf("File not found in dataset %s", filename)
	}

	fileName := helpers.AnonymizeFilepath(datasetFiles[idx].FilePath)
	fileURL := baseURL + "/s3/" + dataset + "/" + fileName

	return fileURL, fileName, nil
}

// GetDatasets is retained for backward compatibility with list/ and
// download_test.go. Deprecated: new code should call apiclient.Client
// via apiclient.New(...). Removed in #677 when callers finish migrating.
func GetDatasets(baseURL, token, version string) ([]string, error) {
	// URL-parse errors are returned unwrapped to preserve legacy behavior
	// (TestListDatasetsNoUrl asserts on the bare "invalid base URL" string).
	u, err := url.ParseRequestURI(baseURL)
	if err != nil || u.Scheme == "" {
		return nil, errors.New("invalid base URL")
	}

	c := apiclient.NewV1Client(apiclient.Config{
		BaseURL: baseURL,
		Token:   token,
		Version: version,
	}, nil)

	datasets, err := c.ListDatasets(context.Background())
	if err != nil {
		// Preserve pre-abstraction error shape: transport/status failures were
		// wrapped as "failed to get datasets, reason: ..."; parse errors
		// already carry their own "failed to parse ..." prefix from
		// V1Client.ListDatasets, so pass those through untouched to avoid
		// double-wrapping.
		if strings.HasPrefix(err.Error(), "failed to parse") {
			return nil, err
		}

		return nil, fmt.Errorf("failed to get datasets, reason: %v", err)
	}

	return datasets, nil
}

// GetFilesInfo is retained for backward compatibility. Preserves v1's
// error-prefix behavior ("failed to get files, reason: ...") that
// existing tests like TestInvalidUrl rely on. Deprecated: call
// apiclient.Client.ListFiles instead. Removed in #677.
func GetFilesInfo(baseURL, dataset, pubKeyBase64, token, version string) ([]File, error) {
	// URL-parse errors are returned unwrapped to preserve legacy behavior
	// (tests like TestFileIdUrl/InvalidUrl and TestListDatasetNoUrl rely on
	// the bare "invalid base URL" string).
	u, err := url.ParseRequestURI(baseURL)
	if err != nil || u.Scheme == "" {
		return nil, errors.New("invalid base URL")
	}

	c := apiclient.NewV1Client(apiclient.Config{
		BaseURL: baseURL,
		Token:   token,
		Version: version,
	}, nil)
	files, err := c.ListFiles(context.Background(), dataset, apiclient.ListFilesOptions{
		LegacyV1PubKey: pubKeyBase64,
	})
	if err != nil {
		// Same shape discrimination as GetDatasets: parse errors from
		// V1Client already carry "failed to parse ..." prefixes, so avoid
		// double-wrapping by passing those through. Transport/status
		// failures keep the legacy "failed to get files, reason: ..."
		// wrapper that callers and TestInvalidUrl depend on.
		if strings.HasPrefix(err.Error(), "failed to parse") {
			return nil, err
		}

		return nil, fmt.Errorf("failed to get files, reason: %v", err)
	}

	return files, nil
}

// getBody returns a stream of the response body and its size
func getBody(requestURL, token, pubKeyBase64 string) (io.ReadCloser, int64, error) {
	req, err := http.NewRequest("GET", requestURL, nil)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to create request, reason: %v", err)
	}

	req.Header.Add("SDA-Client-Version", appVersion)
	req.Header.Add("Authorization", "Bearer "+token)
	req.Header.Add("Content-Type", "application/json")
	if pubKeyBase64 != "" {
		req.Header.Add("Client-Public-Key", pubKeyBase64)
	}

	client := &http.Client{Jar: cookieJar}
	res, err := client.Do(req) // #nosec G704
	if err != nil {
		return nil, 0, fmt.Errorf("failed to get response, reason: %v", err)
	}

	if res.StatusCode != http.StatusOK {
		defer res.Body.Close()
		resBody, _ := io.ReadAll(res.Body)
		if res.StatusCode == http.StatusPreconditionFailed {
			return nil, 0, errors.New(strings.TrimSpace(string(resBody)))
		}

		return nil, 0, fmt.Errorf("server returned status %d", res.StatusCode)
	}

	return res.Body, res.ContentLength, nil
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

func setupCookieJar(u *url.URL) {
	if cd, err := os.UserCacheDir(); err != nil {
		fmt.Fprintln(os.Stderr, "cache dir not set, using current dir")
		cookiePath, _ = filepath.Abs(".sda_cookie")
	} else {
		if err := os.MkdirAll(filepath.Join(cd, "sda-cli"), 0750); err != nil {
			fmt.Fprintln(os.Stderr, "failed to create cache dir, using current dir")
			cookiePath, _ = filepath.Abs(".sda_cookie")
		} else {
			cookiePath = filepath.Join(cd, "sda-cli/sda_cookie")
		}
	}
	cookieJar = cookiejar.NewPersistentJar(
		cookiejar.WithFilePath(cookiePath),
		cookiejar.WithAutoSync(true),
		cookiejar.WithPublicSuffixList(publicsuffix.List),
	)
	if _, err := os.Stat(cookiePath); err == nil {
		cookieString, err := os.ReadFile(cookiePath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to read cookie file: %s", err.Error())
		}

		var parsedCookies []*http.Cookie
		if err := json.Unmarshal(cookieString, &parsedCookies); err == nil && len(parsedCookies) > 0 {
			cookieJar.SetCookies(u, parsedCookies)
		}
	}
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
