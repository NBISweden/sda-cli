package apiclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

// V2Client talks to the v2 SDA download API
// (GET /datasets, /datasets/{id}/files, /files/{id}, etc.).
// Methods fill in across #675, #676, #677. Until then, unimplemented
// methods return a clear "not implemented until #N" error.
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
// #678 replaces error wrapping with RFC 9457 Problem Details parsing.
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
		// Cap the read at 201 bytes: we only surface up to 200 bytes of
		// the body in the error and a hostile or misconfigured server
		// could otherwise stream a large payload into memory just to be
		// truncated. The remainder is intentionally not drained; a bogus
		// error body isn't worth keeping the connection in the pool.
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 201))
		_ = resp.Body.Close()
		body := string(b)
		if len(body) > 200 {
			body = body[:200]
		}

		return nil, fmt.Errorf("server returned status %d: %s", resp.StatusCode, body)
	}

	return resp.Body, nil
}
