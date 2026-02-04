package download

import (
	"bufio"
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
var continueDownload bool
var outDir string
var datasetDownload bool
var pubKey string
var recursiveDownload bool
var fromFile bool
var pubKeyBase64 string

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
	downloadCmd.Flags().BoolVar(&continueDownload, "continue", false, "Skip existing files and continue with the rest")
	downloadCmd.Flags().StringVar(&outDir, "outdir", "", "Directory to output downloaded files")
	downloadCmd.Flags().BoolVar(&datasetDownload, "dataset", false, "Download all the files of the dataset")
	downloadCmd.Flags().StringVar(&pubKey, "pubkey", "", "Path to the public key file to use for encryption of files to download")
	downloadCmd.Flags().BoolVarP(&recursiveDownload, "recursive", "r", false, "Download all content from a folder recursively")
	downloadCmd.Flags().BoolVar(&fromFile, "from-file", false, "Download files from file list")
}

var cookieJar *cookiejar.PersistentJar
var cookiePath string
var appVersion string

// File struct represents the file metadata
type File struct {
	FileID                    string `json:"fileId"`
	DatasetID                 string `json:"datasetId"`
	DisplayFileName           string `json:"displayFileName"`
	FilePath                  string `json:"filePath"`
	FileName                  string `json:"fileName"`
	FileSize                  int    `json:"fileSize"`
	DecryptedFileSize         int    `json:"decryptedFileSize"`
	DecryptedFileChecksum     string `json:"decryptedFileChecksum"`
	DecryptedFileChecksumType string `json:"decryptedFileChecksumType"`
	FileStatus                string `json:"fileStatus"`
	CreatedAt                 string `json:"createdAt"`
	LastModified              string `json:"lastModified"`
}

// Download function downloads files from the SDA by using the
// download's service APIs
func Download(args []string, configPath, version string) error {
	appVersion = version

	if datasetID == "" || URL == "" || configPath == "" {
		return errors.New("missing required arguments, dataset-id, config and url are required")
	}

	u, err := url.Parse(URL)
	if err != nil || u.Scheme == "" {
		return errors.New("invalid base URL")
	}
	setupCookieJar(u)

	// Check if both -recursive and -dataset flags are set
	if recursiveDownload && datasetDownload {
		return errors.New("both -recursive and -dataset flags are set, choose one of them")
	}

	// Check that file(s) are not missing if the -dataset flag is not set
	if len(args) == 0 && !datasetDownload {
		if !recursiveDownload {
			return errors.New("no files provided for download")
		}

		return errors.New("no folders provided for recursive download")
	}

	if datasetDownload && len(args) > 0 {
		return errors.New("files provided with -dataset flag, add either the flag or the file(s), not both")
	}

	if fromFile && len(args) != 1 {
		return errors.New("one file should be provided with the -from-file flag")
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

	helpers.PrintHostBase(config.HostBase)

	switch {
	case datasetDownload:
		err = datasetCase(config.AccessToken)
		if err != nil {
			return err
		}
	case recursiveDownload:
		err = recursiveCase(args, config.AccessToken)
		if err != nil {
			return err
		}
	case fromFile:
		err = fileCase(args, config.AccessToken, true)
		if err != nil {
			return err
		}
	default:
		err = fileCase(args, config.AccessToken, false)
		if err != nil {
			return err
		}
	}

	return nil
}

func datasetCase(token string) error {
	fmt.Println("Downloading all files in the dataset")
	files, err := GetFilesInfo(URL, datasetID, "", token, appVersion)
	if err != nil {
		return err
	}

	for _, file := range files {
		fileName := helpers.AnonymizeFilepath(file.FilePath)
		fileURL := URL + "/s3/" + file.DatasetID + "/" + fileName
		if err != nil {
			return err
		}
		err = downloadFile(fileURL, token, pubKeyBase64, file.FilePath)
		if err != nil {
			return err
		}
	}

	return nil
}

func recursiveCase(args []string, token string) error {
	fmt.Println("Downloading content of the path(s)")
	files, err := GetFilesInfo(URL, datasetID, "", token, appVersion)
	if err != nil {
		return err
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
			if strings.Contains(file.FilePath, dirPath) {
				pathExists = true
				fileName := helpers.AnonymizeFilepath(file.FilePath)
				fileURL := URL + "/s3/" + file.DatasetID + "/" + fileName
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

func fileCase(args []string, token string, fileList bool) error {
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

		if continueDownload {
			if _, err := os.Stat(outputPath); err == nil {
				fmt.Printf("Skipping download to %s, file already exists\n", outputPath)

				continue
			} else if !errors.Is(err, os.ErrNotExist) {
				return err
			}
		}

		fileIDURL, apiFilePath, err := getFileIDURL(URL, token, pubKeyBase64, datasetID, filePath)
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

	if continueDownload {
		if _, err := os.Stat(filePath); !errors.Is(err, os.ErrNotExist) {
			fmt.Printf("Skipping download to %s, file already exists\n", filePath)

			return nil
		}
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
			_ = os.Remove(outFile.Name())
		}
	}()

	// 1 MB buffer
	buf := make([]byte, 1024*1024)
	bufReader := bufio.NewReaderSize(bodyStream, 1024*1024)

	// Progress container
	p := mpb.New(
		mpb.WithRefreshRate(150 * time.Millisecond),
	)

	// Decide which helper to call based on totalSize
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

	if _, err := os.Stat(filePath); err == nil {
		if err := os.Remove(filePath); err != nil {
			return fmt.Errorf("failed to remove existing file %s: %v", filePath, err)
		}
	}

	if err := os.Rename(outFile.Name(), filePath); err != nil {
		return fmt.Errorf("failed to rename partial file %s: %v", outFile.Name(), err)
	}

	downloadSuccessful = true

	return nil
}

func getFileIDURL(baseURL, token, pubKeyBase64, dataset, filename string) (string, string, error) {
	datasetFiles, err := GetFilesInfo(baseURL, dataset, pubKeyBase64, token, appVersion)
	if err != nil {
		return "", "", err
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

func GetDatasets(baseURL, token, version string) ([]string, error) {
	appVersion = version
	u, err := url.ParseRequestURI(baseURL)
	if err != nil || u.Scheme == "" {
		return []string{}, errors.New("invalid base URL")
	}

	setupCookieJar(u)

	datasetsURL := baseURL + "/metadata/datasets"

	bodyStream, _, err := getBody(datasetsURL, token, "")
	if err != nil {
		return []string{}, fmt.Errorf("failed to get datasets, reason: %v", err)
	}
	defer bodyStream.Close()

	var datasets []string
	err = json.NewDecoder(bodyStream).Decode(&datasets)
	if err != nil {
		return []string{}, fmt.Errorf("failed to parse dataset list JSON, reason: %v", err)
	}

	return datasets, nil
}

// GetFilesInfo gets the files of the dataset by using the dataset ID
func GetFilesInfo(baseURL, dataset, pubKeyBase64, token, version string) ([]File, error) {
	appVersion = version
	u, err := url.ParseRequestURI(baseURL)
	if err != nil || u.Scheme == "" {
		return []File{}, errors.New("invalid base URL")
	}

	setupCookieJar(u)

	filesURL := baseURL + "/metadata/datasets/" + dataset + "/files"
	bodyStream, _, err := getBody(filesURL, token, pubKeyBase64)
	if err != nil {
		return []File{}, fmt.Errorf("failed to get files, reason: %v", err)
	}
	defer bodyStream.Close()

	var files []File
	err = json.NewDecoder(bodyStream).Decode(&files)
	if err != nil {
		return []File{}, fmt.Errorf("failed to parse file list JSON, reason: %v", err)
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
	res, err := client.Do(req)
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
