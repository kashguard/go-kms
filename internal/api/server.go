package api

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"

	"github.com/dropbox/godropbox/time2"
	"github.com/kashguard/go-kms/internal/config"
	"github.com/kashguard/go-kms/internal/data/dto"
	"github.com/kashguard/go-kms/internal/data/local"
	"github.com/kashguard/go-kms/internal/i18n"
	"github.com/kashguard/go-kms/internal/kms/audit"
	"github.com/kashguard/go-kms/internal/kms/encryption"
	"github.com/kashguard/go-kms/internal/kms/key"
	"github.com/kashguard/go-kms/internal/kms/policy"
	"github.com/kashguard/go-kms/internal/kms/secret"
	"github.com/kashguard/go-kms/internal/kms/sign"
	"github.com/kashguard/go-kms/internal/kms/storage"
	"github.com/kashguard/go-kms/internal/mailer"
	"github.com/kashguard/go-kms/internal/metrics"
	"github.com/kashguard/go-kms/internal/push"
	"github.com/kashguard/go-kms/internal/util"
	"github.com/labstack/echo/v4"
	"github.com/rs/zerolog/log"

	// Import postgres driver for database/sql package
	_ "github.com/lib/pq"
)

type Router struct {
	Routes     []*echo.Route
	Root       *echo.Group
	Management *echo.Group
	APIV1Auth  *echo.Group
	APIV1Push  *echo.Group
	APIV1KMS   *echo.Group
	WellKnown  *echo.Group
}

// Server is a central struct keeping all the dependencies.
// It is initialized with wire, which handles making the new instances of the components
// in the right order. To add a new component, 3 steps are required:
// - declaring it in this struct
// - adding a provider function in providers.go
// - adding the provider's function name to the arguments of wire.Build() in wire.go
//
// Components labeled as `wire:"-"` will be skipped and have to be initialized after the InitNewServer* call.
// For more information about wire refer to https://pkg.go.dev/github.com/google/wire
type Server struct {
	// skip wire:
	// -> initialized with router.Init(s) function
	Echo   *echo.Echo `wire:"-"`
	Router *Router    `wire:"-"`

	Config  config.Server
	DB      *sql.DB
	Mailer  *mailer.Mailer
	Push    *push.Service
	I18n    *i18n.Service
	Clock   time2.Clock
	Auth    AuthService
	Local   *local.Service
	Metrics *metrics.Service

	// KMS services
	KeyService        key.Service
	EncryptionService encryption.Service
	SignService       sign.Service
	SecretService     secret.Service
	PolicyEngine      policy.Engine
	AuditLogger       audit.Logger
	MetadataStore     storage.MetadataStore
}

// newServerWithComponents is used by wire to initialize the server components.
// Components not listed here won't be handled by wire and should be initialized separately.
// Components which shouldn't be handled must be labeled `wire:"-"` in Server struct.
func newServerWithComponents(
	cfg config.Server,
	db *sql.DB,
	mail *mailer.Mailer,
	pusher *push.Service,
	i18n *i18n.Service,
	clock time2.Clock,
	auth AuthService,
	local *local.Service,
	metrics *metrics.Service,
	keyService key.Service,
	encryptionService encryption.Service,
	signService sign.Service,
	secretService secret.Service,
	policyEngine policy.Engine,
	auditLogger audit.Logger,
	metadataStore storage.MetadataStore,
) *Server {
	return &Server{
		Config:            cfg,
		DB:                db,
		Mailer:            mail,
		Push:              pusher,
		I18n:              i18n,
		Clock:             clock,
		Auth:              auth,
		Local:             local,
		Metrics:           metrics,
		KeyService:        keyService,
		EncryptionService: encryptionService,
		SignService:       signService,
		SecretService:     secretService,
		PolicyEngine:      policyEngine,
		AuditLogger:       auditLogger,
		MetadataStore:     metadataStore,
	}
}

type AuthService interface {
	GetAppUserProfile(ctx context.Context, id string) (*dto.AppUserProfile, error)
	InitPasswordReset(ctx context.Context, request dto.InitPasswordResetRequest) (dto.InitPasswordResetResult, error)
	Login(ctx context.Context, request dto.LoginRequest) (dto.LoginResult, error)
	Logout(ctx context.Context, request dto.LogoutRequest) error
	Refresh(ctx context.Context, request dto.RefreshRequest) (dto.LoginResult, error)
	Register(ctx context.Context, request dto.RegisterRequest) (dto.RegisterResult, error)
	CompleteRegister(ctx context.Context, request dto.CompleteRegisterRequest) (dto.LoginResult, error)
	DeleteUserAccount(ctx context.Context, request dto.DeleteUserAccountRequest) error
	ResetPassword(ctx context.Context, request dto.ResetPasswordRequest) (dto.LoginResult, error)
	UpdatePassword(ctx context.Context, request dto.UpdatePasswordRequest) (dto.LoginResult, error)
}

func NewServer(config config.Server) *Server {
	s := &Server{
		Config: config,
	}

	return s
}

func (s *Server) Ready() bool {
	// 如果 Secret 服务未启用，允许 SecretService 为 nil
	// 创建一个临时 Server 副本用于初始化检查，将 SecretService 设置为非 nil
	checkServer := *s
	if !s.Config.KMS.EnableSecretService && s.SecretService == nil {
		// 创建一个空的实现来通过初始化检查
		// 使用一个简单的占位符实现
		checkServer.SecretService = &noopSecretService{}
	}

	if err := util.IsStructInitialized(&checkServer); err != nil {
		log.Debug().Err(err).Msg("Server is not fully initialized")
		return false
	}

	return true
}

// noopSecretService 是一个空的 SecretService 实现，用于在 Secret 服务未启用时通过初始化检查
type noopSecretService struct{}

func (n *noopSecretService) CreateSecret(ctx context.Context, keyID string, data []byte) (string, error) {
	return "", errors.New("secret service is not enabled")
}

func (n *noopSecretService) GetSecret(ctx context.Context, keyID string) ([]byte, error) {
	return nil, errors.New("secret service is not enabled")
}

func (n *noopSecretService) UpdateSecret(ctx context.Context, keyID string, data []byte) error {
	return errors.New("secret service is not enabled")
}

func (n *noopSecretService) DeleteSecret(ctx context.Context, keyID string) error {
	return errors.New("secret service is not enabled")
}

func (n *noopSecretService) SecretExists(ctx context.Context, keyID string) (bool, error) {
	return false, errors.New("secret service is not enabled")
}

func (s *Server) Start() error {
	if !s.Ready() {
		return errors.New("server is not ready")
	}

	if err := s.Echo.Start(s.Config.Echo.ListenAddress); err != nil {
		return fmt.Errorf("failed to start echo server: %w", err)
	}

	return nil
}

func (s *Server) Shutdown(ctx context.Context) []error {
	log.Warn().Msg("Shutting down server")

	var errs []error

	if s.DB != nil {
		log.Debug().Msg("Closing database connection")

		if err := s.DB.Close(); err != nil && !errors.Is(err, sql.ErrConnDone) {
			log.Error().Err(err).Msg("Failed to close database connection")
			errs = append(errs, err)
		}
	}

	if s.Echo != nil {
		log.Debug().Msg("Shutting down echo server")

		if err := s.Echo.Shutdown(ctx); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error().Err(err).Msg("Failed to shutdown echo server")
			errs = append(errs, err)
		}
	}

	return errs
}
