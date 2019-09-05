# echo_azure_ad_auth

This middleware is used to integrate authentication of echo with Azure AD

How to use :

go get github.com/fuhongbo/echo_azure_ad_auth

```
package main

import (
	ECHO_AZURE_AD_AUTH "github.com/fuhongbo/echo_azure_ad_auth"
	"github.com/gorilla/sessions"
	"github.com/labstack/echo"
	"github.com/labstack/echo-contrib/session"
	"net/http"
)


func main(){

	e := echo.New()
	fstore:=sessions.NewFilesystemStore("",[]byte("something-very-secret"))
	fstore.MaxLength(0)
	e.Use(session.Middleware(fstore))
	e.Debug=true

	adconfig:=&ECHO_AZURE_AD_AUTH.AzureADConfig{
		ClientID:     "************",
		ClientSecret: "************",,
		RedirectURL:  "http://localhost:8080/callback",
		AuthURL:      "https://login.chinacloudapi.cn/common/oauth2/authorize",
		TokenURL:     "https://login.chinacloudapi.cn/common/oauth2/token",
		EchoInstance: e,
		Resource:     "https://graph.chinacloudapi.cn",
		CallbackMethod:"/callback",
	}
	adconfig.InitOAuth()

	e.Use(adconfig.OAuth)



	e.GET("/", func(c echo.Context) error {

		return c.JSON(http.StatusOK,"Hello "+ECHO_AZURE_AD_AUTH.GetUserInfo(c).DisplayName)
	})

	e.Logger.Fatal(e.Start(":8080"))
}

```