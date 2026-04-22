package apiclient

// v2File is the v2 server's FileInfo wire shape. Differs from apiclient.File:
//   - Scalar DecryptedFileSize → DecryptedSize (int64 here vs int in v1)
//   - DecryptedFileChecksum/Type → Checksums array
//   - New DownloadURL (server-provided; clients must not construct /files/{id})
//   - Drops v1-only fields (DisplayFileName, etc.)
//
// Conversion to the shared File type happens at the V2Client boundary.
type v2File struct {
	FileID        string     `json:"fileId"`
	FilePath      string     `json:"filePath"`
	Size          int64      `json:"size"`
	DecryptedSize int64      `json:"decryptedSize"`
	Checksums     []Checksum `json:"checksums"`
	DownloadURL   string     `json:"downloadUrl"`
}

// datasetListResponse is the v2 response for GET /datasets.
// nextPageToken is nullable per swagger — use a pointer.
type datasetListResponse struct {
	Datasets      []string `json:"datasets"`
	NextPageToken *string  `json:"nextPageToken"`
}

// fileListResponse is the v2 response for GET /datasets/{id}/files.
type fileListResponse struct {
	Files         []v2File `json:"files"`
	NextPageToken *string  `json:"nextPageToken"`
}

// datasetInfoResponse is the v2 wire response for GET /datasets/{id}.
// Currently a mirror of the public apiclient.DatasetInfo, but kept as a
// separate wire type so v2-only schema drift (added/renamed fields, extra
// metadata) can be absorbed here without rippling into the shared
// apiclient surface. The file count uses json:"files" per swagger (not
// "fileCount" as the Go field name might suggest). The swagger schema
// also lists "date" as required; we intentionally don't decode it since
// the CLI doesn't surface it today — add it here first when that changes.
type datasetInfoResponse struct {
	DatasetID string `json:"datasetId"`
	FileCount int    `json:"files"`
	Size      int64  `json:"size"`
}

// toFile converts a v2File into the shared apiclient.File.
// Maps the Checksums array to the legacy scalar fields:
// prefer sha256 if present, else first entry.
// DisplayFileName is not populated (v2 doesn't return it).
func (f v2File) toFile() File {
	out := File{
		FileID:            f.FileID,
		FilePath:          f.FilePath,
		DecryptedFileSize: int(f.DecryptedSize),
		DownloadURL:       f.DownloadURL,
	}
	for _, c := range f.Checksums {
		if c.Type == "sha256" {
			out.DecryptedFileChecksum = c.Checksum
			out.DecryptedFileChecksumType = c.Type

			return out
		}
	}
	if len(f.Checksums) > 0 {
		out.DecryptedFileChecksum = f.Checksums[0].Checksum
		out.DecryptedFileChecksumType = f.Checksums[0].Type
	}

	return out
}
