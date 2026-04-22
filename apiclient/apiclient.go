package apiclient

import (
	"context"
	"errors"
	"fmt"

	"go.nhat.io/cookiejar"
)

// Config holds per-call configuration.
type Config struct {
	BaseURL string // e.g. "https://download.example.org"
	Token   string // bearer token (raw, no "Bearer " prefix)
	Version string // sda-cli version; sent as SDA-Client-Version header
}

// Client is the SDA download API abstraction for list-family operations.
// The DownloadFile method joins this interface in #677 alongside v2
// download implementation.
type Client interface {
	ListDatasets(ctx context.Context) ([]string, error)
	ListFiles(ctx context.Context, datasetID string, opts ListFilesOptions) ([]File, error)
	DatasetInfo(ctx context.Context, datasetID string) (DatasetInfo, error)
}

// Option customises the Client returned by New. Options only affect the
// versions they apply to; unknown options are silently ignored by
// versions that do not honour them (WithV1CookieJar is v1-only).
type Option func(*clientOpts)

type clientOpts struct {
	v1CookieJar *cookiejar.PersistentJar
}

// WithV1CookieJar hands V1Client an externally-managed persistent cookie
// jar instead of letting it lazy-init its own. Required when the caller
// (e.g. download/download.go) also runs the legacy downloadFile path so
// metadata listing and /s3 transfer share the same in-memory jar and
// avoid clobbering each other via AutoSync to the shared on-disk file.
func WithV1CookieJar(jar *cookiejar.PersistentJar) Option {
	return func(o *clientOpts) { o.v1CookieJar = jar }
}

// ValidateVersion returns the same error shape as New for a given
// version string without constructing a client. Callers can use it to
// fail fast on unsupported versions before doing other setup work
// (e.g. cookie-jar init) that is wasted when the command is going to
// error out anyway.
func ValidateVersion(version string) error {
	switch version {
	case "v1":
		return nil
	case "v2":
		return errors.New("--api-version v2 is not yet implemented; see #663 for progress")
	default:
		return fmt.Errorf("unsupported --api-version %q (v1 or v2)", version)
	}
}

// New returns a Client for the requested version.
// Today accepts "v1" only; "v2" errors. Extended in #675 to return a V2Client.
func New(cfg Config, version string, opts ...Option) (Client, error) {
	if err := ValidateVersion(version); err != nil {
		return nil, err
	}

	var o clientOpts
	for _, opt := range opts {
		opt(&o)
	}
	// ValidateVersion above guarantees version is "v1" (the only
	// branch that returns a client in this implementation).
	return NewV1Client(cfg, o.v1CookieJar), nil
}
