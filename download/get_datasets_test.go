package download

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetDatasets(t *testing.T) {
	// Create a test httpTestServer
	httpTestServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		// Set the response status code
		w.WriteHeader(http.StatusOK)
		// Set the response body
		fmt.Fprint(w, `["https://doi.example/ty009.sfrrss/600.45asasga"]`)
	}))
	defer httpTestServer.Close()

	// Test
	datasets, err := GetDatasets(httpTestServer.URL, accessToken)
	require.NoError(t, err)
	assert.Equal(t, datasets, []string{"https://doi.example/ty009.sfrrss/600.45asasga"})
}
