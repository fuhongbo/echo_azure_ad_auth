package ECHO_AZURE_AD_AUTH

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/gob"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"

	"github.com/gorilla/sessions"
	"github.com/labstack/echo"
	session "github.com/labstack/echo-contrib/session"
	"golang.org/x/oauth2"
)

type AzureADConfig struct {
	ClientID       string
	ClientSecret   string
	RedirectURL    string
	CallbackMethod string
	AuthURL        string
	TokenURL       string
	EchoInstance   *echo.Echo
	Resource       string
}

var (
	clientID string
	Config   *oauth2.Config
)

type User struct {
	Email        string `json:"userPrincipalName"`
	DisplayName  string `json:"displayName"`
	MailNickname string `json:"mailNickname"`
}

func init() {
	gob.Register(&User{})
	gob.Register(&oauth2.Token{})
}

func GetUserInfo(c echo.Context) *User {
	sess, _ := session.Get("session", c)
	user := sess.Values["user"]

	if user != nil {
		return user.(*User)

	} else {
		return &User{}
	}
}

func SessionState(session *sessions.Session) string {
	return base64.StdEncoding.EncodeToString(sha256.New().Sum([]byte(session.ID)))
}

func (ca *AzureADConfig) InitOAuth() {
	Config = &oauth2.Config{
		ClientID:     ca.ClientID,
		ClientSecret: ca.ClientSecret, // no client secret
		RedirectURL:  ca.RedirectURL,

		Endpoint: oauth2.Endpoint{
			AuthURL:  ca.AuthURL,
			TokenURL: ca.TokenURL,
		},

		Scopes: []string{"User.Read"},
	}

	ca.EchoInstance.GET(ca.CallbackMethod, func(c echo.Context) error {

		sess, _ := session.Get("session", c)

		if c.Request().FormValue("state") != SessionState(sess) {

			return c.JSON(http.StatusBadRequest, "invalid callback state")
		}

		form := url.Values{}
		form.Set("grant_type", "authorization_code")
		form.Set("client_id", ca.ClientID)
		form.Set("code", c.Request().FormValue("code"))
		form.Set("client_secret", Config.ClientSecret)
		form.Set("redirect_uri", ca.RedirectURL)
		form.Set("resource", ca.Resource)

		tokenReq, err := http.NewRequest(http.MethodPost, ca.TokenURL, strings.NewReader(form.Encode()))
		if err != nil {
			return fmt.Errorf("error creating token request: %v", err)
		}
		tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		resp, err := http.DefaultClient.Do(tokenReq)
		if err != nil {
			return fmt.Errorf("error performing token request: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode >= 400 {

			body, _ := ioutil.ReadAll(resp.Body)
			fmt.Println(string(body))
			return fmt.Errorf("token response was %s", resp.Status)
		}

		var token oauth2.Token
		if err := json.NewDecoder(resp.Body).Decode(&token); err != nil {
			return fmt.Errorf("error decoding JSON response: %v", err)
		}

		sess.Values["token"] = &token
		sess.Values["user"] = getUserInfo(token.AccessToken, ca.Resource+"/me?api-version=1.6")

		if err := sessions.Save(c.Request(), c.Response()); err != nil {
			return fmt.Errorf("error saving session: %v", err)
		}
		c.Redirect(http.StatusFound, "/")
		return nil
	})
}

func (ca *AzureADConfig) OAuth(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		if c.Path() == ca.CallbackMethod {
			return next(c)
		}
		sess, _ := session.Get("session", c)

		if v, ok := sess.Values["token"]; ok && v != nil {
			return next(c)
		} else {
			return c.Redirect(http.StatusTemporaryRedirect, Config.AuthCodeURL(SessionState(sess), oauth2.AccessTypeOnline))
		}

		return nil
	}
}

func getUserInfo(token string, url string) *User {

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		fmt.Printf("error creating token request: %v", err)
		return nil
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Printf("error performing token request: %v", err)
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {

		body, _ := ioutil.ReadAll(resp.Body)
		fmt.Println(string(body))

	}

	var user User
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		println(err.Error())
	}

	return &user
}
