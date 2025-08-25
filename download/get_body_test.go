package download

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/suite"
)

type GetBodyTestSuite struct {
	suite.Suite
	httpTestServer *httptest.Server
}

func (suite *GetBodyTestSuite) SetupSuite() {
	// Create a test httpTestServer
	suite.httpTestServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Set the response status code
		w.WriteHeader(http.StatusOK)
		// Set the response body
		fmt.Fprint(w, "test response")
	}))
}

func (suite *GetBodyTestSuite) TearDownSuite() {
	suite.httpTestServer.Close()
}

func TestGetBodyTestSuite(t *testing.T) {
	suite.Run(t, new(GetBodyTestSuite))
}

func (suite *GetBodyTestSuite) TestGetBodyNoPublicKey() {
	// Make a request to the test httpTestServer with an empty public key
	body, err := getBody(suite.httpTestServer.URL, "test-token", "")
	if err != nil {
		suite.T().Errorf("getBody returned an error: %v", err)
	}

	// Check the response body
	expectedBody := "test response"
	if string(body) != expectedBody {
		suite.T().Errorf("getBody returned incorrect response body, got: %s, want: %s", string(body), expectedBody)
	}
}
func (suite *GetBodyTestSuite) TestGetBodyWithPublicKey() {
	// Make a request to the test httpTestServer using a public key
	body, err := getBody(suite.httpTestServer.URL, "test-token", "test-public-key")
	if err != nil {
		suite.T().Errorf("getBody returned an error: %v", err)
	}

	// Check the response body
	expectedBody := "test response"
	if string(body) != expectedBody {
		suite.T().Errorf("getBody returned incorrect response body, got: %s, want: %s", string(body), expectedBody)
	}
}
