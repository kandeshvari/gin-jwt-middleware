package jwt

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/robbert229/jwt"
)

type Login struct {
	Username string `form:"username" json:"username" binding:"required"`
	Password string `form:"password" json:"password" binding:"required"`
}

// Refresh token storage interface
type IRefreshTokenStorage interface {
	Issue() (string, error)
	// Call to check is refresh token already expired
	IsExpire(token string) bool
	// Add/Update refresh token in
	Update(token string, timeout time.Duration) error
	// Delete refresh token from storage
	Delete(token string) bool
}

type GinMiddleware struct {
	// secret key
	SecretKey string
	// header name in request that contains our token
	Header string
	// algorithm (see github.com/robbert229/jwt for details)
	Algorithm *jwt.Algorithm
	// access token ttl
	Timeout time.Duration
	// refresh token ttl
	RefreshTimeout time.Duration
	// func for handle unauthorized responses
	Unauthorized func(*gin.Context, int, string)
	// authentication function
	Authenticator func(userID string, password string, c *gin.Context) (interface{}, bool)
	// authorization function
	Authorizator func(payload interface{}, c *gin.Context) bool
	// refresh token storage instance
	RefreshTokenStorage IRefreshTokenStorage
}

// Initialize middleware struct
func (m *GinMiddleware) Init() error {
	if m.Header == "" {
		m.Header = "Authorization"
	}

	if m.Algorithm == nil {
		alg := jwt.HmacSha256(m.SecretKey)
		m.Algorithm = &alg
	}

	if m.Timeout == 0 {
		m.Timeout = time.Hour
	}

	if m.RefreshTimeout == 0 {
		m.RefreshTimeout = time.Hour * 24
	}

	if m.Unauthorized == nil {
		m.Unauthorized = func(c *gin.Context, code int, message string) {
			c.JSON(code, gin.H{
				"code":    code,
				"message": message,
			})
		}
	}

	if m.Authorizator == nil {
		m.Authorizator = func(payload interface{}, c *gin.Context) bool { return true }
	}

	if m.RefreshTokenStorage == nil {
		return errors.New("refresh token storage is required")
	}

	return nil
}

// MiddlewareFunc makes GinMiddleware implement the Gin Middleware interface.
func (m *GinMiddleware) MiddlewareFunc() gin.HandlerFunc {
	if err := m.Init(); err != nil {
		return func(c *gin.Context) {
			m.unauthorized(c, http.StatusInternalServerError, err.Error())
			return
		}
	}

	return func(c *gin.Context) {
		m.middlewareImpl(c)
		return
	}
}

// Helper: Extract payload from gic.Context
func ExtractPayload(c *gin.Context) map[string]interface{} {
	payload, exists := c.Get("JWT_PAYLOAD")
	//log.Printf("payload: %#v, exists: %t\n", payload, exists)

	if !exists {
		return make(map[string]interface{}, 0)
	}
	return payload.(map[string]interface{})
}

// Generate new access token and send it to client
func (m *GinMiddleware) IssueAccessToken(refreshToken string, payload interface{}, c *gin.Context) {
	// and issue new token
	claims := jwt.NewClaim()
	claims.Set("payload", payload)
	claims.Set("refresh_token", refreshToken)
	err := m.RefreshTokenStorage.Update(refreshToken, m.RefreshTimeout)
	if err != nil {
		m.unauthorized(c, http.StatusInternalServerError, "Refresh Token update failed")
		return
	}
	expire := time.Now().Add(m.Timeout)
	claims.Set("expire", expire.Unix())

	token, err := m.Algorithm.Encode(claims)
	if err != nil {
		m.unauthorized(c, http.StatusInternalServerError, "Create JWT Token failed")
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"token":  token,
		"expire": expire.Format(time.RFC3339),
	})

}

/* Handlers */

// Handler for token refresh action
func (m *GinMiddleware) RefreshHandler(c *gin.Context) {
	// retrieve claims from token
	claims, err := m.getClaims(c)
	if err != nil {
		m.unauthorized(c, http.StatusUnauthorized, err.Error())
		return
	}

	// get refresh token
	refreshToken, err := claims.Get("refresh_token")
	if err != nil {
		m.unauthorized(c, http.StatusUnauthorized, err.Error())
		return
	}

	// check refresh timeout field
	if m.RefreshTokenStorage.IsExpire(refreshToken.(string)) {
		//if time.Now().Unix() > tokenStorage[refreshToken.(string)] {
		m.unauthorized(c, http.StatusUnauthorized, "refresh token expired")
		return
	}

	// get payload from claims
	payload, err := claims.Get("payload")
	if err != nil {
		m.unauthorized(c, http.StatusUnauthorized, err.Error())
		return
	}

	m.IssueAccessToken(refreshToken.(string), payload, c)
}

// Handler for login action
func (m *GinMiddleware) LoginHandler(c *gin.Context) {
	m.Init()

	var credentials Login

	if c.BindJSON(&credentials) != nil {
		m.unauthorized(c, http.StatusBadRequest, "Missing Username or Password")
		return
	}

	if m.Authenticator == nil {
		m.unauthorized(c, http.StatusInternalServerError, "Missing define authenticator func")
		return
	}

	userID, ok := m.Authenticator(credentials.Username, credentials.Password, c)

	if !ok {
		m.unauthorized(c, http.StatusUnauthorized, "Incorrect Username / Password")
		return
	}

	// Create the refresh token
	refreshToken, err := m.RefreshTokenStorage.Issue()
	if err != nil {
		m.unauthorized(c, http.StatusInternalServerError, "Unable to issue refresh token")
		return
	}
	m.IssueAccessToken(refreshToken, userID, c)
}

/* Internal functions */

// Middleware implementation
func (m *GinMiddleware) middlewareImpl(c *gin.Context) {

	// retrieve claims from token
	claims, err := m.getClaims(c)
	if err != nil {
		m.unauthorized(c, http.StatusUnauthorized, err.Error())
		return
	}

	// check expire
	expire, err := claims.Get("expire")
	if err != nil {
		m.unauthorized(c, http.StatusUnauthorized, err.Error())
		return
	}

	// check expire field
	if time.Now().Unix() > int64(expire.(float64)) {
		m.unauthorized(c, http.StatusUnauthorized, "token expired")
		return
	}

	// get payload from claims
	payload, err := claims.Get("payload")
	if err != nil {
		m.unauthorized(c, http.StatusUnauthorized, err.Error())
		return
	}
	c.Set("JWT_PAYLOAD", payload)

	if !m.Authorizator(payload, c) {
		m.unauthorized(c, http.StatusForbidden, "You don't have permission to access.")
		return
	}

	c.Next()
}

// Get token from header, parse it and extract claims
func (m *GinMiddleware) getClaims(c *gin.Context) (*jwt.Claims, error) {
	authHeader := c.Request.Header.Get(m.Header)

	if authHeader == "" {
		return nil, errors.New("auth header empty")
	}

	parts := strings.SplitN(authHeader, " ", 2)
	if !(len(parts) == 2 && parts[0] == "Bearer") {
		return nil, errors.New("invalid auth header")
	}

	claims, err := m.Algorithm.Decode(parts[1])
	if err != nil {
		return nil, errors.New("cant decode auth header")
	}
	return claims, nil
}

// Construct and send unauthorized response
func (m *GinMiddleware) unauthorized(c *gin.Context, code int, message string) {
	c.Header("WWW-Authenticate", "JWT realm=gin jwt")
	c.Abort()
	m.Unauthorized(c, code, message)
	return
}
