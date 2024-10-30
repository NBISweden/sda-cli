package version

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type VersionTests struct {
	suite.Suite
}

func TestVersionTestSuite(t *testing.T) {
	suite.Run(t, new(VersionTests))
}

func (suite *VersionTests) TestGetVersion() {
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"html_url": "https://github.com/NBISweden/sda-cli/releases/tag/v0.1.3","name": "v0.1.3","published_at": "2024-09-19T09:23:33Z"}`))
	}))
	defer mockServer.Close()
	url = mockServer.URL

	err := Version("1.0.0")
	assert.NoError(suite.T(), err)
}

func (suite *VersionTests) TestGetVersion_newerAvailable() {
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"html_url": "https://github.com/NBISweden/sda-cli/releases/tag/v0.1.3","name": "v0.1.3","published_at": "2024-09-19T09:23:33Z"}`))
	}))
	defer mockServer.Close()
	url = mockServer.URL

	storeStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := Version("0.0.1")
	assert.NoError(suite.T(), err)

	w.Close()
	out, _ := io.ReadAll(r)
	os.Stdout = storeStdout

	assert.Contains(suite.T(), string(out), "Newer version if sda-cli is avaiable")
}

func (suite *VersionTests) TestGetVersion_badGateway() {
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer mockServer.Close()
	url = mockServer.URL

	storeStderr := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w

	err := Version("0.0.3")
	assert.NoError(suite.T(), err)

	w.Close()
	out, _ := io.ReadAll(r)
	os.Stderr = storeStderr

	assert.Equal(suite.T(), string(out), "failed to fetch releases, reson: 502 Bad Gateway\n")
}

func (suite *VersionTests) TestGetVersion_networkTimeout() {
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(20 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer mockServer.Close()
	url = mockServer.URL
	timeout = 10 * time.Millisecond

	storeStderr := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w

	err := Version("0.0.3")
	assert.NoError(suite.T(), err)

	w.Close()
	out, _ := io.ReadAll(r)
	os.Stderr = storeStderr

	assert.Contains(suite.T(), string(out), "context deadline exceeded")
}
