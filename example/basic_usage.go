package main

import (
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/kandeshvari/gin-jwt-middleware"
)

func helloHandler(c *gin.Context) {
	payload := jwt.ExtractPayload(c)
	c.JSON(200, gin.H{
		"userID":   payload["user_id"],
		"userRole": payload["user_role"],
		"text":     "Hello World.",
	})
}

// User demo
type User struct {
	UserId   int    `json:"user_id"`
	UserRole string `json:"user_role"`
}

func authenticator(userId string, password string, _ *gin.Context) (interface{}, bool) {
	if (userId == "admin" && password == "admin") || (userId == "test" && password == "test") {
		return &User{
			UserId:   42,
			UserRole: "admin",
		}, true
	}

	return nil, false
}

func main() {
	port := os.Getenv("PORT")
	r := gin.New()
	r.Use(gin.Logger())
	r.Use(gin.Recovery())

	if port == "" {
		port = "8000"
	}

	authMW := &jwt.GinMiddleware{
		SecretKey:           "some secret string",
		Timeout:             time.Minute * 15,
		RefreshTimeout:      time.Hour,
		Authenticator:       authenticator,
		RefreshTokenStorage: NewRefreshTokenStorage(),
	}

	r.POST("/login", authMW.LoginHandler)
	r.GET("/refresh_token", authMW.RefreshHandler)

	auth := r.Group("/auth")
	auth.Use(authMW.MiddlewareFunc())
	{
		auth.GET("/hello", helloHandler)
	}

	if err := http.ListenAndServe(":"+port, r); err != nil {
		log.Fatal(err)
	}
}
