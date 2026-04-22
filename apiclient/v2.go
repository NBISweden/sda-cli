package apiclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// V2Client talks to the v2 SDA download API
// (GET /datasets, /datasets/{id}/files, /files/{id}, etc.).
type V2Client struct {
	cfg  Config
	http *http.Client
}

// NewV2Client constructs a V2Client. HTTP client is a plain net/http.Client
// (no cookie jar — v2 is stateless bearer-token auth, no Location-based
// redirects requiring cookies).
func NewV2Client(cfg Config) *V2Client {
	return &V2Client{
		cfg:  cfg,
		http: &http.Client{},
	}
}

// ListDatasets implements Client. Uses the paginate[T] helper to walk all
// pages of GET /datasets, following nextPageToken until the server returns
// null or an empty string.
func (c *V2Client) ListDatasets(ctx context.Context) ([]string, error) {
	return paginate(ctx, func(ctx context.Context, pageToken *string) ([]string, *string, error) {
		u := c.cfg.BaseURL + "/datasets"
		if pageToken != nil {
			u += "?" + url.Values{"pageToken": {*pageToken}}.Encode()
		}
		body, err := c.getJSON(ctx, u)
		if err != nil {
			return nil, nil, err
		}
		defer body.Close() //nolint:errcheck

		var resp datasetListResponse
		if err := json.NewDecoder(body).Decode(&resp); err != nil {
			return nil, nil, fmt.Errorf("failed to decode /datasets response: %w", err)
		}

		return resp.Datasets, resp.NextPageToken, nil
	})
}

// ListFiles implements Client. Walks all pages of GET /datasets/{id}/files,
// optionally applying the v2 server-side filters (exact filePath, or recursive
// pathPrefix). The two filters are mutually exclusive per v2's contract;
// we reject that combo client-side for a friendlier message than the
// server's 400.
func (c *V2Client) ListFiles(ctx context.Context, datasetID string, opts ListFilesOptions) ([]File, error) {
	if opts.ExactPath != "" && opts.PathPrefix != "" {
		return nil, errors.New("ListFilesOptions.ExactPath and .PathPrefix are mutually exclusive")
	}

	return paginate(ctx, func(ctx context.Context, pageToken *string) ([]File, *string, error) {
		u := c.cfg.BaseURL + "/datasets/" + url.PathEscape(datasetID) + "/files"
		q := url.Values{}
		if opts.ExactPath != "" {
			q.Set("filePath", opts.ExactPath)
		}
		if opts.PathPrefix != "" {
			q.Set("pathPrefix", opts.PathPrefix)
		}
		if pageToken != nil {
			q.Set("pageToken", *pageToken)
		}
		if enc := q.Encode(); enc != "" {
			u += "?" + enc
		}
		body, err := c.getJSON(ctx, u)
		if err != nil {
			return nil, nil, err
		}
		defer body.Close() //nolint:errcheck

		var resp fileListResponse
		if err := json.NewDecoder(body).Decode(&resp); err != nil {
			return nil, nil, fmt.Errorf("failed to decode /datasets/%s/files response: %w", datasetID, err)
		}
		out := make([]File, len(resp.Files))
		for i, f := range resp.Files {
			out[i] = f.toFile()
		}

		return out, resp.NextPageToken, nil
	})
}

// DownloadFile implements Client. Resolves req.UserArg (either a file path
// or a fileId) via resolveFile, then follows the server-provided DownloadURL
// with the X-C4GH-Public-Key header. Returns the resolved File so callers
// can use its canonical FilePath for the on-disk name (a userArg that was
// a bare fileId is not usable as a filename). 403 responses (from either
// the list resolution step or the download GET) are flattened to an
// ambiguous "does not exist or access denied" error to preserve the
// server's existence-leakage contract. Caller is responsible for closing
// the body.
func (c *V2Client) DownloadFile(ctx context.Context, req DownloadRequest) (DownloadResult, error) {
	if req.PublicKeyBase64 == "" {
		return DownloadResult{}, errors.New("v2 downloads require --pubkey (X-C4GH-Public-Key header)")
	}

	target, err := c.resolveFile(ctx, req.DatasetID, req.UserArg)
	if err != nil {
		// Flatten 403 from the list-resolution step to preserve the server's
		// existence-leakage contract — a forbidden dataset/file must look
		// identical to a missing one.
		var apiErr *APIError
		if errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusForbidden {
			return DownloadResult{}, fmt.Errorf("dataset/file does not exist or access denied: %s", req.UserArg)
		}

		return DownloadResult{}, err
	}
	if target.FileID == "" {
		return DownloadResult{}, fmt.Errorf("dataset/file does not exist or access denied: %s", req.UserArg)
	}
	if target.DownloadURL == "" {
		return DownloadResult{}, fmt.Errorf("server returned empty downloadUrl for %s", req.UserArg)
	}

	// Resolve the server-provided DownloadURL against BaseURL so we tolerate
	// both relative paths (e.g. "/files/f1") and the absolute URLs a server
	// might return for pre-signed storage redirects. Naive concatenation
	// breaks on absolute URLs and on trailing/leading-slash mismatches.
	base, err := url.Parse(c.cfg.BaseURL)
	if err != nil {
		return DownloadResult{}, fmt.Errorf("invalid base URL %q: %w", c.cfg.BaseURL, err)
	}
	ref, err := url.Parse(target.DownloadURL)
	if err != nil {
		return DownloadResult{}, fmt.Errorf("server returned invalid downloadUrl %q: %w", target.DownloadURL, err)
	}
	resolved := base.ResolveReference(ref)

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, resolved.String(), nil)
	if err != nil {
		return DownloadResult{}, err
	}
	// Authorization is only safe on the BaseURL host. If the server
	// redirects to a different origin (e.g. a pre-signed S3 URL) the
	// presigned signature is self-authenticating and leaking the bearer
	// token to that host is both unnecessary and risky.
	if resolved.Host == base.Host {
		httpReq.Header.Set("Authorization", "Bearer "+c.cfg.Token)
	}
	httpReq.Header.Set("X-C4GH-Public-Key", req.PublicKeyBase64)
	if c.cfg.Version != "" {
		httpReq.Header.Set("User-Agent", "sda-cli/"+c.cfg.Version)
	}

	resp, err := c.http.Do(httpReq) // #nosec G704
	if err != nil {
		return DownloadResult{}, fmt.Errorf("http request: %w", err)
	}
	// Partial-Content without a Range request is a server bug; accepting it
	// would rename a truncated .part as a complete file.
	if resp.StatusCode != http.StatusOK {
		err := parseErrorResponse(resp)
		if resp.StatusCode == http.StatusForbidden {
			return DownloadResult{}, fmt.Errorf("dataset/file does not exist or access denied: %s", req.UserArg)
		}

		return DownloadResult{}, err
	}

	return DownloadResult{File: target, Body: resp.Body, ContentLength: resp.ContentLength}, nil
}

// resolveFile converts UserArg (path or fileId) into an apiclient.File so
// callers can use its DownloadURL. Uses the exact filePath filter for paths;
// for bare ids, falls back to list + match (v2 has no exact-id filter).
// Returns a zero File (FileID == "") if not found.
func (c *V2Client) resolveFile(ctx context.Context, datasetID, userArg string) (File, error) {
	isPath := strings.Contains(userArg, "/") || strings.HasSuffix(userArg, ".c4gh")
	if isPath {
		files, err := c.ListFiles(ctx, datasetID, ListFilesOptions{ExactPath: userArg})
		if err != nil {
			return File{}, err
		}
		if len(files) == 0 {
			return File{}, nil
		}

		return files[0], nil
	}
	// Bare id: list + match. v2 has no exact-id filter.
	files, err := c.ListFiles(ctx, datasetID, ListFilesOptions{})
	if err != nil {
		return File{}, err
	}
	for _, f := range files {
		if f.FileID == userArg {
			return f, nil
		}
	}

	return File{}, nil
}

// DatasetInfo implements Client. Calls GET /datasets/{id} and returns the
// v2-only dataset metadata (file count + total decrypted size).
func (c *V2Client) DatasetInfo(ctx context.Context, datasetID string) (DatasetInfo, error) {
	u := c.cfg.BaseURL + "/datasets/" + url.PathEscape(datasetID)
	body, err := c.getJSON(ctx, u)
	if err != nil {
		return DatasetInfo{}, err
	}
	defer body.Close() //nolint:errcheck

	var resp datasetInfoResponse
	if err := json.NewDecoder(body).Decode(&resp); err != nil {
		return DatasetInfo{}, fmt.Errorf("failed to decode /datasets/%s response: %w", datasetID, err)
	}

	// Structural type conversion: fails to compile if datasetInfoResponse
	// ever drifts from DatasetInfo, which forces the decoupling rationale
	// in v2_types.go to be re-examined rather than silently papered over.
	return DatasetInfo(resp), nil
}

// getJSON performs an authenticated GET returning the response body.
// Non-2xx responses are converted to *APIError via parseErrorResponse so
// callers can do typed status-code checks with errors.As.
func (c *V2Client) getJSON(ctx context.Context, reqURL string) (io.ReadCloser, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.cfg.Token)
	req.Header.Set("Accept", "application/json")
	if c.cfg.Version != "" {
		req.Header.Set("User-Agent", "sda-cli/"+c.cfg.Version)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http request: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, parseErrorResponse(resp)
	}

	return resp.Body, nil
}
