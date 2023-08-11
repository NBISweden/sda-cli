package login

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"gopkg.in/ini.v1"
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
        The login target can be one of the following: 
			https://login.bp.nbis.se/
			https://login.test.fega.nbis.se/
			https://login.gdi.nbis.se/`

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

type Result struct {
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
	LoginResult     *Result
	UserInfo        *UserInfo
	wellKnown       *OIDCWellKnown
	deviceLogin     *DeviceLoginResponse
}

type AuthInfo struct {
	ClientID  string `json:"client_id"`
	OidcURI   string `json:"oidc_uri"`
	PublicKey string `json:"public_key"`
	InboxURI  string `json:"inbox_uri"`
}

// requests the /info endpoint to fetch the parameters needed for login
func GetAuthInfo(baseURL string) (*AuthInfo, error) {
	url := baseURL + "/info"
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var result AuthInfo
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(body, &result)
	if err != nil {
		return nil, err
	}

	return &result, nil
}

// creates a .sda-cli-session file and updates its values
func (login *DeviceLogin) UpdateConfigFile() error {

	_, err := os.Create(".sda-cli-session")
	if err != nil {
		return err
	}
	cfg, err := ini.Load(".sda-cli-session")
	if err != nil {
		return err
	}

	s3Config, err := login.GetS3Config()
	if err != nil {
		return err
	}

	err = ini.ReflectFrom(cfg, s3Config)
	if err != nil {
		return err
	}
	err = cfg.SaveTo(".sda-cli-session")
	if err != nil {
		return err
	}

	return nil
}

func NewLogin(args []string) error {
	deviceLogin, err := NewDeviceLogin(args)
	if err != nil {
		return fmt.Errorf("failed to contact authentication service")
	}
	err = deviceLogin.Login()
	if err != nil {
		return fmt.Errorf("Login failed")
	}
	fmt.Printf("Logged in as %v\n", deviceLogin.UserInfo.Name)

	return err
}

// NewDeviceLogin() returns a new `DeviceLogin` with the given `url` and
// `clientID` set.
func NewDeviceLogin(args []string) (DeviceLogin, error) {

	var url string
	err := Args.Parse(args[1:])
	if err != nil {
		return DeviceLogin{}, errors.New("failed parsing arguments")
	}
	if len(Args.Args()) == 1 {
		url = Args.Args()[0]
	}
	info, err := GetAuthInfo(url)
	if err != nil {
		return DeviceLogin{}, errors.New("failed to get auth Info")
	}

	return DeviceLogin{BaseURL: info.OidcURI, ClientID: info.ClientID, PollingInterval: 2, S3Target: info.InboxURI}, nil
}

// open opens the specified URL in the default browser of the user.
func open(url string) error {
	var cmd string
	var args []string

	switch runtime.GOOS {
	case "windows":
		cmd = "cmd"
		args = []string{"/c", "start"}
	case "darwin":
		cmd = "open"
	default: // "linux", "freebsd", "openbsd", "netbsd"
		cmd = "xdg-open"
	}
	args = append(args, url)

	return exec.Command(cmd, args...).Start()
}

// Login() does a full login by fetching the remote configuration, starting the
// login procedure, and then waiting for the user to complete login.
func (login *DeviceLogin) Login() error {

	var err error
	login.wellKnown, err = login.getWellKnown()
	if err != nil {
		return fmt.Errorf("failed to fetch .well-known configuration: %v", err)
	}

	login.deviceLogin, err = login.startDeviceLogin()
	if err != nil {
		return fmt.Errorf("failed to start device login: %v", err)
	}
	expires := time.Duration(login.deviceLogin.ExpiresIn * int(time.Second))
	fmt.Printf("Login started (expires in %v minutes)\n", expires.Minutes())

	err = open(login.deviceLogin.VerificationURL)
	if err != nil {
		return fmt.Errorf("failed to open login URL: %v", err)
	}

	loginResult, err := login.waitForLogin()
	if err != nil {
		return err
	}
	login.LoginResult = loginResult

	login.UserInfo, err = login.getUserInfo()
	if err != nil {
		return err
	}

	err = login.UpdateConfigFile()
	if err != nil {
		return err
	}

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
func (login *DeviceLogin) waitForLogin() (*Result, error) {

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

			var loginResult *Result
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
