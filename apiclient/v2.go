package apiclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
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

// ListDatasets implements Client. Single-page only here; pagination via the
// paginate[T] helper arrives in #676. Returning an explicit error when
// nextPageToken != null prevents silently truncating results.
func (c *V2Client) ListDatasets(ctx context.Context) ([]string, error) {
	body, err := c.getJSON(ctx, c.cfg.BaseURL+"/datasets")
	if err != nil {
		return nil, err
	}
	defer body.Close() //nolint:errcheck

	var resp datasetListResponse
	if err := json.NewDecoder(body).Decode(&resp); err != nil {
		return nil, fmt.Errorf("failed to decode /datasets response: %w", err)
	}
	if resp.NextPageToken != nil && *resp.NextPageToken != "" {
		return nil, errors.New("pagination not yet implemented (coming in #676)")
	}

	return resp.Datasets, nil
}

// ListFiles implements Client. Not implemented until #676.
func (c *V2Client) ListFiles(_ context.Context, _ string, _ ListFilesOptions) ([]File, error) {
	return nil, errors.New("V2Client.ListFiles not implemented until #676")
}

// DatasetInfo implements Client. Not implemented until #676.
func (c *V2Client) DatasetInfo(_ context.Context, _ string) (DatasetInfo, error) {
	return DatasetInfo{}, errors.New("V2Client.DatasetInfo not implemented until #676")
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
		b, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		body := string(b)
		if len(body) > 200 {
			body = body[:200]
		}

		return nil, fmt.Errorf("server returned status %d: %s", resp.StatusCode, body)
	}

	return resp.Body, nil
}
