package apiclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"go.nhat.io/cookiejar"
	"golang.org/x/net/publicsuffix"
)

// V1Client talks to the v1 /metadata/datasets and /s3/... endpoints.
type V1Client struct {
	cfg       Config
	http      *http.Client
	jar       *cookiejar.PersistentJar // persistent; same jar as legacy download.setupCookieJar
	cookiePth string                   // resolved path, stored for parity

	// injectedJar, when non-nil, is used verbatim by ensureJar instead of
	// allocating a second PersistentJar. Callers that already maintain a
	// cookie jar (e.g. download/download.go for the downloadFile path)
	// pass theirs in via NewV1Client so metadata and /s3 requests share
	// the same in-memory cookie state — matches pre-abstraction behavior where
	// a single package-level jar served both paths.
	injectedJar *cookiejar.PersistentJar
}

// NewV1Client constructs a V1Client. If injectedJar is non-nil the
// client will reuse it instead of initialising its own persistent jar on
// first use. HTTP client + jar are otherwise initialized lazily inside
// ensureJar (called on every public method) to stay cheap at
// construction and to avoid forcing UserCacheDir lookups during tests
// that inject c.http directly.
func NewV1Client(cfg Config, injectedJar *cookiejar.PersistentJar) *V1Client {
	return &V1Client{cfg: cfg, injectedJar: injectedJar}
}

// SetHTTPClientForTest injects an http.Client, bypassing the persistent
// cookie jar. Use only in tests. The name is intentionally awkward.
func (c *V1Client) SetHTTPClientForTest(h *http.Client) {
	c.http = h
}

// resolveCookiePath mirrors download.setupCookieJar's path resolution
// EXACTLY so apiclient and legacy callers share the same on-disk jar.
// Do not add per-host suffixes or /tmp fallbacks.
func resolveCookiePath() string {
	cd, err := os.UserCacheDir()
	if err != nil {
		fmt.Fprintln(os.Stderr, "cache dir not set, using current dir")
		p, _ := filepath.Abs(".sda_cookie")

		return p
	}
	if err := os.MkdirAll(filepath.Join(cd, "sda-cli"), 0750); err != nil {
		fmt.Fprintln(os.Stderr, "failed to create cache dir, using current dir")
		p, _ := filepath.Abs(".sda_cookie")

		return p
	}

	return filepath.Join(cd, "sda-cli/sda_cookie")
}

// ensureJar sets up cookiejar and http client on first use. If c.http
// is already set (test injection), ensureJar is a no-op. If the caller
// supplied an injectedJar via NewV1Client, that jar is reused so
// metadata and /s3 paths share the same in-memory cookie state.
func (c *V1Client) ensureJar(u *url.URL) {
	if c.http != nil {
		return
	}
	if c.injectedJar != nil {
		c.jar = c.injectedJar
		c.http = &http.Client{Jar: c.jar}

		return
	}
	c.cookiePth = resolveCookiePath()
	c.jar = cookiejar.NewPersistentJar(
		cookiejar.WithFilePath(c.cookiePth),
		cookiejar.WithAutoSync(true),
		cookiejar.WithPublicSuffixList(publicsuffix.List),
	)
	// Load existing cookies from the on-disk file, matching the legacy
	// behavior (download.setupCookieJar:551-560).
	if _, err := os.Stat(c.cookiePth); err == nil {
		if buf, err := os.ReadFile(c.cookiePth); err == nil {
			var parsed []*http.Cookie
			if jerr := json.Unmarshal(buf, &parsed); jerr == nil && len(parsed) > 0 {
				c.jar.SetCookies(u, parsed)
			}
		}
	}
	c.http = &http.Client{Jar: c.jar}
}

// ListDatasets implements Client.
func (c *V1Client) ListDatasets(ctx context.Context) ([]string, error) {
	u, err := url.ParseRequestURI(c.cfg.BaseURL)
	if err != nil || u.Scheme == "" {
		return nil, errors.New("invalid base URL")
	}
	c.ensureJar(u)

	body, _, err := c.getBody(ctx, c.cfg.BaseURL+"/metadata/datasets", "")
	if err != nil {
		return nil, err
	}
	defer body.Close() //nolint:errcheck

	var datasets []string
	if err := json.NewDecoder(body).Decode(&datasets); err != nil {
		return nil, fmt.Errorf("failed to parse dataset list JSON, reason: %v", err)
	}

	return datasets, nil
}

// ListFiles implements Client.
func (c *V1Client) ListFiles(ctx context.Context, datasetID string, opts ListFilesOptions) ([]File, error) {
	if opts.ExactPath != "" || opts.PathPrefix != "" {
		return nil, ErrNotSupportedOnV1
	}
	u, err := url.ParseRequestURI(c.cfg.BaseURL)
	if err != nil || u.Scheme == "" {
		return nil, errors.New("invalid base URL")
	}
	c.ensureJar(u)

	body, _, err := c.getBody(ctx, c.cfg.BaseURL+"/metadata/datasets/"+datasetID+"/files", opts.LegacyV1PubKey)
	if err != nil {
		return nil, err
	}
	defer body.Close() //nolint:errcheck

	var files []File
	if err := json.NewDecoder(body).Decode(&files); err != nil {
		return nil, fmt.Errorf("failed to parse file list JSON, reason: %v", err)
	}

	return files, nil
}

// DatasetInfo implements Client. v1 has no /datasets/{id} endpoint.
func (c *V1Client) DatasetInfo(_ context.Context, _ string) (DatasetInfo, error) {
	return DatasetInfo{}, ErrNotSupportedOnV1
}

// getBody is the v1 HTTP helper. Headers, error shape, and 412 handling
// match the legacy download.getBody (download/download.go:483-514) verbatim.
//
// SDA-Client-Version, Authorization, Content-Type are always set.
// Client-Public-Key is set only when pubKeyBase64 != "".
// On HTTP 412 the server's response body is returned as the error message.
// On other non-200 responses the error is "server returned status N".
func (c *V1Client) getBody(ctx context.Context, requestURL, pubKeyBase64 string) (io.ReadCloser, int64, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL, nil)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to create request, reason: %v", err)
	}

	req.Header.Add("SDA-Client-Version", c.cfg.Version)
	req.Header.Add("Authorization", "Bearer "+c.cfg.Token)
	req.Header.Add("Content-Type", "application/json")
	if pubKeyBase64 != "" {
		req.Header.Add("Client-Public-Key", pubKeyBase64)
	}

	res, err := c.http.Do(req) // #nosec G704
	if err != nil {
		return nil, 0, fmt.Errorf("failed to get response, reason: %v", err)
	}

	if res.StatusCode != http.StatusOK {
		defer res.Body.Close() //nolint:errcheck
		resBody, _ := io.ReadAll(res.Body)
		if res.StatusCode == http.StatusPreconditionFailed {
			return nil, 0, errors.New(strings.TrimSpace(string(resBody)))
		}

		return nil, 0, fmt.Errorf("server returned status %d", res.StatusCode)
	}

	return res.Body, res.ContentLength, nil
}
