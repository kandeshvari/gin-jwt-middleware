package main

import (
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/kandeshvari/gin-jwt-middleware"
	"github.com/satori/go.uuid"
)

type RefreshTokenStorage struct {
	jwt.IRefreshTokenStorage
	rw      *sync.RWMutex
	storage map[string]int64
}

func NewRefreshTokenStorage() *RefreshTokenStorage {
	return &RefreshTokenStorage{
		storage: make(map[string]int64),
		rw:      &sync.RWMutex{},
	}
}

func (ts *RefreshTokenStorage) Issue() (string, error) {
	return uuid.NewV4().String(), nil
}

func (ts *RefreshTokenStorage) IsExpire(token string) bool {
	return false
}

func (ts *RefreshTokenStorage) Update(token string, refreshTimeout time.Duration, payload map[string]interface{}, c *gin.Context) error {
	ts.rw.Lock()
	ts.storage[token] = time.Now().Add(refreshTimeout).Unix()
	ts.rw.Unlock()

	return nil
}

func (ts *RefreshTokenStorage) Delete(token string) error {
	return nil
}

// Revoke refresh token
func (ts *RefreshTokenStorage) Revoke(token string) error {
	return nil
}

// Check is refresh token was revoked
func (ts *RefreshTokenStorage) IsRevoked(token string) bool {
	return false
}
