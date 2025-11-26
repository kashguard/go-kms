package api

import (
	"database/sql"
	"fmt"
	"testing"
	"time"

	"github.com/dropbox/godropbox/time2"
	"github.com/kashguard/go-kms/internal/auth"
	"github.com/kashguard/go-kms/internal/config"
	"github.com/kashguard/go-kms/internal/i18n"
	"github.com/kashguard/go-kms/internal/kms/audit"
	"github.com/kashguard/go-kms/internal/kms/encryption"
	"github.com/kashguard/go-kms/internal/kms/hsm"
	"github.com/kashguard/go-kms/internal/kms/hsm/software"
	"github.com/kashguard/go-kms/internal/kms/key"
	"github.com/kashguard/go-kms/internal/kms/policy"
	"github.com/kashguard/go-kms/internal/kms/secret"
	"github.com/kashguard/go-kms/internal/kms/sign"
	"github.com/kashguard/go-kms/internal/kms/storage"
	"github.com/kashguard/go-kms/internal/mailer"
	"github.com/kashguard/go-kms/internal/persistence"
	"github.com/kashguard/go-kms/internal/push"
	"github.com/kashguard/go-kms/internal/push/provider"
	"github.com/rs/zerolog/log"
)

// PROVIDERS - define here only providers that for various reasons (e.g. cyclic dependency) can't live in their corresponding packages
// or for wrapping providers that only accept sub-configs to prevent the requirements for defining providers for sub-configs.
// https://github.com/google/wire/blob/main/docs/guide.md#defining-providers

// NewPush creates an instance of the push service and registers the configured push providers.
func NewPush(cfg config.Server, db *sql.DB) (*push.Service, error) {
	pusher := push.New(db)

	if cfg.Push.UseFCMProvider {
		fcmProvider, err := provider.NewFCM(cfg.FCMConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to create FCM provider: %w", err)
		}
		pusher.RegisterProvider(fcmProvider)
	}

	if cfg.Push.UseMockProvider {
		log.Warn().Msg("Initializing mock push provider")
		mockProvider := provider.NewMock(push.ProviderTypeFCM)
		pusher.RegisterProvider(mockProvider)
	}

	if pusher.GetProviderCount() < 1 {
		log.Warn().Msg("No providers registered for push service")
	}

	return pusher, nil
}

func NewClock(t ...*testing.T) time2.Clock {
	var clock time2.Clock

	useMock := len(t) > 0 && t[0] != nil

	if useMock {
		clock = time2.NewMockClock(time.Now())
	} else {
		clock = time2.DefaultClock
	}

	return clock
}

func NewAuthService(config config.Server, db *sql.DB, clock time2.Clock) *auth.Service {
	return auth.NewService(config, db, clock)
}

func NewMailer(config config.Server) (*mailer.Mailer, error) {
	return mailer.NewWithConfig(config.Mailer, config.SMTP)
}

func NewDB(config config.Server) (*sql.DB, error) {
	return persistence.NewDB(config.Database)
}

func NewI18N(config config.Server) (*i18n.Service, error) {
	return i18n.New(config.I18n)
}

func NoTest() []*testing.T {
	return nil
}

// KMS Providers

// NewHSMAdapter creates HSM adapter based on configuration
//
//nolint:ireturn // returning interface is intentional for abstraction
func NewHSMAdapter(cfg config.Server, _ *sql.DB) (hsm.Adapter, error) {
	switch cfg.KMS.HSMType {
	case "software":
		// SoftHSM
		//nolint:gosec // HSMSlot is a configuration value, overflow is acceptable
		return software.NewAdapter(cfg.KMS.HSMLibrary, uint(cfg.KMS.HSMSlot), cfg.KMS.HSMPIN)
	default:
		return nil, fmt.Errorf("unsupported HSM type: %s", cfg.KMS.HSMType)
	}
}

// NewMetadataStore creates metadata store based on configuration
//
//nolint:ireturn // returning interface is intentional for abstraction
func NewMetadataStore(cfg config.Server, db *sql.DB) (storage.MetadataStore, error) {
	switch cfg.KMS.StorageBackend {
	case "postgresql":
		return storage.NewPostgreSQLStore(db), nil
	default:
		return nil, fmt.Errorf("unsupported storage backend: %s", cfg.KMS.StorageBackend)
	}
}

// NewPolicyEngine creates policy engine
//
//nolint:ireturn // returning interface is intentional for abstraction
func NewPolicyEngine(metadataStore storage.MetadataStore) policy.Engine {
	return policy.NewEngine(metadataStore)
}

// NewAuditLogger creates audit logger
//
//nolint:ireturn // returning interface is intentional for abstraction
func NewAuditLogger(metadataStore storage.MetadataStore) audit.Logger {
	return audit.NewLogger(metadataStore)
}

// NewKeyService creates key service
//
//nolint:ireturn // returning interface is intentional for abstraction
func NewKeyService(
	db *sql.DB,
	hsmAdapter hsm.Adapter,
	metadataStore storage.MetadataStore,
	policyEngine policy.Engine,
	auditLogger audit.Logger,
) (key.Service, error) {
	return key.NewService(db, hsmAdapter, metadataStore, policyEngine, auditLogger)
}

// NewEncryptionService creates encryption service
//
//nolint:ireturn // returning interface is intentional for abstraction
func NewEncryptionService(
	keyService key.Service,
	hsmAdapter hsm.Adapter,
	metadataStore storage.MetadataStore,
	policyEngine policy.Engine,
	auditLogger audit.Logger,
) (encryption.Service, error) {
	return encryption.NewService(keyService, hsmAdapter, metadataStore, policyEngine, auditLogger)
}

// NewSignService creates sign service
//
//nolint:ireturn // returning interface is intentional for abstraction
func NewSignService(
	keyService key.Service,
	hsmAdapter hsm.Adapter,
	metadataStore storage.MetadataStore,
	policyEngine policy.Engine,
	auditLogger audit.Logger,
) (sign.Service, error) {
	return sign.NewService(keyService, hsmAdapter, metadataStore, policyEngine, auditLogger)
}

// NewSecretService creates secret service
//
//nolint:ireturn // returning interface is intentional for abstraction
func NewSecretService(
	encryptionService encryption.Service,
	keyService key.Service,
	metadataStore storage.MetadataStore,
	policyEngine policy.Engine,
	auditLogger audit.Logger,
	cfg config.Server,
) (secret.Service, error) {
	secretKMSKeyID := cfg.KMS.SecretKMSKeyID
	if secretKMSKeyID == "" {
		// 如果没有配置，使用默认的密钥别名查找
		if cfg.KMS.SecretKMSKeyAlias != "" {
			// 这里需要根据 alias 查找 keyID，暂时返回错误
			return nil, fmt.Errorf("KMS_SECRET_KEY_ID is required when using secret service")
		}
		return nil, fmt.Errorf("KMS_SECRET_KEY_ID is required")
	}
	return secret.NewService(encryptionService, keyService, metadataStore, policyEngine, auditLogger, secretKMSKeyID)
}
