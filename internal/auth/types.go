package auth

import (
	"time"

	"github.com/kashguard/go-kms/internal/data/dto"
)

type Result struct {
	Token      string
	User       *dto.User
	ValidUntil time.Time
	Scopes     []string
}
