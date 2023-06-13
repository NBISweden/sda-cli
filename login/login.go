package login

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/NBISweden/sda-cli/helpers"
	log "github.com/sirupsen/logrus"
)

// Help text and command line flags.

// Usage text that will be displayed as command line help text when using the
// `help login` command
var Usage = `

USAGE: %s login <login-target>

login:
    logs in to the SDA using the provided login target.
`

// ArgHelp is the suffix text that will be displayed after the argument list in
// the module help
var ArgHelp = `
    [login-target]
        The login target can be one of the following: bp.nbis.se`

// Args is a flagset that needs to be exported so that it can be written to the
// main program help
var Args = flag.NewFlagSet("login", flag.ExitOnError)

type S3Config struct {
	AccessKey            string `ini:"access_key"`
	SecretKey            string `ini:"secret_key"`
	AccessToken          string `ini:"access_token"`
	HostBucket           string `ini:"host_bucket"`
	HostBase             string `ini:"host_base"`
	MultipartChunkSizeMb int64  `ini:"multipart_chunk_size_mb"`
	GuessMimeType        bool   `ini:"guess_mime_type"`
	Encoding             string `ini:"encoding"`
	CheckSslCertificate  bool   `ini:"check_ssl_certificate"`
	CheckSslHostname     bool   `ini:"check_ssl_hostname"`
	UseHTTPS             bool   `ini:"use_https"`
	SocketTimeout        int    `ini:"socket_timeout"`
	HumanReadableSizes   bool   `ini:"human_readable_sizes"`
}

type OIDCWellKnown struct {
	TokenEndpoint               string `json:"token_endpoint"`
	DeviceAuthorizationEndpoint string `json:"device_authorization_endpoint"`
}

type DeviceLoginResponse struct {
	VerificationURL string `json:"verification_uri_complete"`
	DeviceCode      string `json:"device_code"`
	ExpiresIn       int    `json:"expires_in"`
}

type LoginResult struct {
	AccessToken      string `json:"access_token"`
	IDToken          string `json:"id_token"`
	Scope            string `json:"scope"`
	TokenType        string `json:"token_type"`
	ExpiresIn        int    `json:"expires_in"`
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

type UserInfo struct {
	Sub               string   `json:"sub"`
	Name              string   `json:"name"`
	PreferredUsername string   `json:"preferred_username"`
	GivenName         string   `json:"given_name"`
	FamilyName        string   `json:"family_name"`
	Email             string   `json:"email"`
	EmailVerified     bool     `json:"email_verified"`
	Ga4ghPassportV1   []string `json:"ga4gh_passport_v1"`
}

type DeviceLogin struct {
	BaseURL         string
	ClientID        string
	S3Target        string
	PollingInterval int
	LoginResult     *LoginResult
	UserInfo        *UserInfo
	wellKnown       *OIDCWellKnown
	deviceLogin     *DeviceLoginResponse
}

// NewDeviceLogin() returns a new `DeviceLogin` with the given `url` and
// `clientID` set.
func NewDeviceLogin(url, clientID, s3Target string) DeviceLogin {
	return DeviceLogin{BaseURL: url, ClientID: clientID, PollingInterval: 2, S3Target: s3Target}
}

// Login() does a full login by fetching the remote configuration, starting the
// login procedure, and then waiting for the user to complete login.
func (login *DeviceLogin) Login(args []string) error {

	var err error

	// Call ParseArgs to take care of all the flag parsing
	err = helpers.ParseArgs(args, Args)
	if err != nil {
		return err
	}

	// Args() returns the argument, which is the url.
	url := Args.Args()
	if len(url) != 1 {
		return fmt.Errorf("No URL provided as argument")
	}
	login.BaseURL = url[0]

	login.wellKnown, err = login.getWellKnown()
	if err != nil {
		return fmt.Errorf("failed to fetch .well-known configuration: %v", err)
	}

	login.deviceLogin, err = login.startDeviceLogin()
	if err != nil {
		return fmt.Errorf("failed to start device login: %v", err)
	}
	expires := time.Duration(login.deviceLogin.ExpiresIn * int(time.Second))
	log.Infof("Login started (expires in %v minutes)", expires.Minutes())
	log.Infof("Go to %v to finish logging in.", login.deviceLogin.VerificationURL)

	loginResult, err := login.waitForLogin()
	if err != nil {
		return err
	}
	login.LoginResult = loginResult

	login.UserInfo, err = login.getUserInfo()

	return err
}

// S3Config() returns an
func (login *DeviceLogin) GetS3Config() (*S3Config, error) {
	if login.LoginResult.AccessToken == "" {
		return nil, errors.New("no login token available for config")
	}
	return &S3Config{
		AccessKey:            login.UserInfo.Sub,
		SecretKey:            login.UserInfo.Sub,
		AccessToken:          login.LoginResult.AccessToken,
		HostBucket:           login.S3Target,
		HostBase:             login.S3Target,
		MultipartChunkSizeMb: 512,
		GuessMimeType:        false,
		Encoding:             "UTF-8",
		CheckSslCertificate:  false,
		CheckSslHostname:     false,
		UseHTTPS:             true,
		SocketTimeout:        30,
		HumanReadableSizes:   true,
	}, nil
}

func (login *DeviceLogin) getUserInfo() (*UserInfo, error) {

	if login.LoginResult.AccessToken == "" {
		return nil, errors.New("login token required to fetch userinfo")
	}

	req, err := http.NewRequest("GET", login.BaseURL+"/userinfo", nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %v", login.LoginResult.AccessToken))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		err = fmt.Errorf("status code: %v", resp.StatusCode)
		return nil, fmt.Errorf("request failed: %v", err)
	}

	var userinfo *UserInfo
	err = json.Unmarshal(body, &userinfo)
	return userinfo, err
}

// getWellKnown() makes a GET request to the `.well-known/openid-configuration`
// endpoint of BaseURL and returns the result as `OIDCWellKnown`.
func (login *DeviceLogin) getWellKnown() (*OIDCWellKnown, error) {
	wellKnownURL := fmt.Sprintf("%v/.well-known/openid-configuration", login.BaseURL)
	resp, err := http.Get(wellKnownURL)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var wellKnownConfig *OIDCWellKnown
	err = json.Unmarshal(body, &wellKnownConfig)
	return wellKnownConfig, err
}

// startDeviceLogin() starts a device login towards the URLs in login.wellKnown
// and sets the login.deviceLogin
func (login *DeviceLogin) startDeviceLogin() (*DeviceLoginResponse, error) {

	loginBody := fmt.Sprintf("response_type=device_code&client_id=%v"+
		"&scope=openid ga4gh_passport_v1 profile email", login.ClientID)

	req, err := http.NewRequest("POST",
		login.wellKnown.DeviceAuthorizationEndpoint, strings.NewReader(loginBody))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		err = fmt.Errorf("status code: %v", resp.StatusCode)
		return nil, fmt.Errorf("request failed: %v", err)
	}

	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var loginResponse *DeviceLoginResponse
	err = json.Unmarshal(body, &loginResponse)

	return loginResponse, err
}

// waitForLogin() waits for the remote OIDC server to verify the completed login
// by polling
func (login *DeviceLogin) waitForLogin() (*LoginResult, error) {

	body := fmt.Sprintf("grant_type=urn:ietf:params:oauth:grant-type:device_code"+
		"&client_id=%v&device_code=%v", login.ClientID, login.deviceLogin.DeviceCode)

	expirationTime := time.Now().Unix() + int64(login.deviceLogin.ExpiresIn)

	for {
		time.Sleep(time.Duration(login.PollingInterval) * time.Second)

		req, err := http.NewRequest("POST", login.wellKnown.TokenEndpoint,
			strings.NewReader(body))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return nil, fmt.Errorf("failure to fetch login token: %v", err)
		}

		if resp.StatusCode == 200 {
			defer resp.Body.Close()
			respBody, err := io.ReadAll(resp.Body)
			if err != nil {
				return nil, err
			}

			var loginResult *LoginResult
			err = json.Unmarshal(respBody, &loginResult)
			if err != nil {
				return nil, err
			}

			return loginResult, nil
		}

		if expirationTime <= time.Now().Unix() {

			break
		}
	}
	return nil, errors.New("login timed out")
}
