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

	"github.com/NBISweden/sda-cli/helpers"
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

// DownloadFile implements Client. Resolves req.UserArg (either a file
// path or a fileId) via ListFiles + legacy substring match, then GETs
// /s3/{dataset}/{filePath}. Returns the resolved File so callers can
// derive the output filename from canonical metadata rather than from
// UserArg (which may be a bare fileId). Caller is responsible for
// closing the returned body.
func (c *V1Client) DownloadFile(ctx context.Context, req DownloadRequest) (DownloadResult, error) {
	// Forward the caller-supplied pubkey so the metadata GET emits
	// Client-Public-Key — mirrors legacy getFileIDURL → GetFilesInfo.
	// Wrap list-resolution failures with the legacy "failed to get
	// files, reason: ..." prefix that scripts and the download.go shim
	// have relied on since before the apiclient abstraction.
	files, err := c.ListFiles(ctx, req.DatasetID, ListFilesOptions{
		LegacyV1PubKey: req.PublicKeyBase64,
	})
	if err != nil {
		return DownloadResult{}, fmt.Errorf("failed to get files, reason: %v", err)
	}
	target, err := v1MatchFile(files, req.UserArg)
	if err != nil {
		return DownloadResult{}, err
	}

	// The v1 /s3 server expects the user-prefix (e.g. "user_example.com/…")
	// already stripped — legacy download.getFileIDURL ran AnonymizeFilepath
	// on target.FilePath before building the URL. Preserve that behavior so
	// datasets whose files carry a user prefix don't 404 on v1 download.
	reqURL := c.cfg.BaseURL + "/s3/" + url.PathEscape(req.DatasetID) + "/" + helpers.AnonymizeFilepath(target.FilePath)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return DownloadResult{}, err
	}
	httpReq.Header.Set("Authorization", "Bearer "+c.cfg.Token)
	// SDA-Client-Version is emitted on every v1 call by legacy getBody.
	if c.cfg.Version != "" {
		httpReq.Header.Set("SDA-Client-Version", c.cfg.Version)
	}
	if req.PublicKeyBase64 != "" {
		httpReq.Header.Set("Client-Public-Key", req.PublicKeyBase64)
	}

	resp, err := c.http.Do(httpReq) // #nosec G704
	if err != nil {
		return DownloadResult{}, err
	}
	// Partial-Content without a Range request is a server bug; treat as a
	// non-success to avoid renaming a truncated .part as a complete file.
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 201))
		_ = resp.Body.Close()
		// Legacy getBody surfaces 412 bodies verbatim — some sda-download
		// paths return actionable messages (e.g. token expired) in the body.
		if resp.StatusCode == http.StatusPreconditionFailed {
			return DownloadResult{}, errors.New(strings.TrimSpace(string(b)))
		}
		body := string(b)
		if len(body) > 200 {
			body = body[:200]
		}

		return DownloadResult{}, fmt.Errorf("server returned status %d: %s", resp.StatusCode, body)
	}

	return DownloadResult{File: target, Body: resp.Body, ContentLength: resp.ContentLength}, nil
}

// v1MatchFile mirrors the substring-match logic from the retired
// download.getFileIDURL. Known to be imprecise; v2 uses an exact
// filePath filter instead. Semantics are unchanged from the legacy
// code — we just house it here now.
func v1MatchFile(files []File, userArg string) (File, error) {
	if strings.Contains(userArg, "/") {
		if !strings.HasSuffix(userArg, ".c4gh") {
			userArg += ".c4gh"
		}
		for _, f := range files {
			if strings.Contains(f.FilePath, userArg) {
				return f, nil
			}
		}
	} else {
		for _, f := range files {
			if strings.Contains(f.FileID, userArg) {
				return f, nil
			}
		}
	}

	return File{}, fmt.Errorf("file not found in dataset: %s", userArg)
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
