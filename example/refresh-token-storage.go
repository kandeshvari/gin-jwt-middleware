package main

import (
	"github.com/kandeshvari/gin-jwt-middleware"
	"github.com/satori/go.uuid"
	"sync"
	"time"
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

func (ts *RefreshTokenStorage) Update(token string, timeout time.Duration) error {
	ts.rw.Lock()
	ts.storage[token] = time.Now().Add(timeout).Unix()
	ts.rw.Unlock()

	return nil
}

func (ts *RefreshTokenStorage) Delete(token string) bool {
	return true
}
