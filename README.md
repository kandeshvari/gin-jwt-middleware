Gin JWT middleware
==================

Very simple but useful implementation of JWT for gin framework as middleware.

Key option of this implementation - you can use access-token to refresh it within RefreshTimeout time

Using `github.com/robbert229/jwt` for token manipulation

Little code from `github.com/appleboy/gin-jwt` was used

## Usage

see `example` directory

Minimal requirements: 
- Implement Authenticator handler
- Implement IRefreshTokenStorage 
