package secret

import (
	"github.com/pkg/errors"
)

var (
	ErrSecretNotFound      = errors.New("secret not found")
	ErrSecretAlreadyExists = errors.New("secret already exists")
	ErrInvalidKMSKey       = errors.New("invalid KMS key")
	ErrEncryptionFailed    = errors.New("encryption failed")
	ErrDecryptionFailed    = errors.New("decryption failed")
)
