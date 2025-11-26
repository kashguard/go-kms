package sign

import (
	"context"
	"crypto/sha256"
	"crypto/sha512"

	"github.com/kashguard/go-kms/internal/kms/audit"
	"github.com/kashguard/go-kms/internal/kms/hsm"
	"github.com/kashguard/go-kms/internal/kms/key"
	"github.com/kashguard/go-kms/internal/kms/policy"
	"github.com/kashguard/go-kms/internal/kms/storage"
	"github.com/pkg/errors"
)

const (
	algorithmED25519 = "ED25519"
)

var (
	ErrKeyNotFound      = errors.New("key not found")
	ErrKeyDisabled      = errors.New("key is disabled")
	ErrInvalidSignature = errors.New("invalid signature")
	ErrInvalidKeyType   = errors.New("invalid key type for signing")
	ErrInvalidAlgorithm = errors.New("invalid signing algorithm")
)

// Service 签名验证服务接口
type Service interface {
	Sign(ctx context.Context, req *SignRequest) (*SignResponse, error)
	Verify(ctx context.Context, req *VerifyRequest) (*VerifyResponse, error)
}

// service 签名验证服务实现
type service struct {
	keyService    key.Service
	hsmAdapter    hsm.Adapter
	metadataStore storage.MetadataStore
	policyEngine  policy.Engine
	auditLogger   audit.Logger
}

// NewService 创建新的签名验证服务
//
//nolint:ireturn // returning interface is intentional for abstraction
func NewService(
	keyService key.Service,
	hsmAdapter hsm.Adapter,
	metadataStore storage.MetadataStore,
	policyEngine policy.Engine,
	auditLogger audit.Logger,
) (Service, error) {
	return &service{
		keyService:    keyService,
		hsmAdapter:    hsmAdapter,
		metadataStore: metadataStore,
		policyEngine:  policyEngine,
		auditLogger:   auditLogger,
	}, nil
}

// Sign 对消息进行签名
func (s *service) Sign(ctx context.Context, req *SignRequest) (*SignResponse, error) {
	// 获取密钥元数据
	keyMetadata, err := s.keyService.GetKey(ctx, req.KeyID)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get key metadata")
	}

	// 验证密钥状态
	if keyMetadata.KeyState != key.KeyStateEnabled {
		return nil, ErrKeyDisabled
	}

	// 验证密钥类型（只支持非对称密钥）
	if keyMetadata.KeyType != key.KeyTypeECCSecp256k1 &&
		keyMetadata.KeyType != key.KeyTypeECCP256 &&
		keyMetadata.KeyType != key.KeyTypeEd25519 {
		return nil, ErrInvalidKeyType
	}

	// 验证权限
	if keyMetadata.PolicyID != "" {
		if err := s.policyEngine.EvaluatePolicy(ctx, keyMetadata.PolicyID, "use_key"); err != nil {
			return nil, errors.Wrap(err, "policy evaluation failed")
		}
	}

	// 验证算法
	if err := s.validateAlgorithm(keyMetadata.KeyType, req.Algorithm); err != nil {
		return nil, err
	}

	// 获取主版本密钥句柄
	primaryVersion, err := s.metadataStore.GetPrimaryKeyVersion(ctx, req.KeyID)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get primary key version")
	}

	// 处理消息（根据模式）
	digest := req.Message
	if req.Mode == "RAW" {
		// RAW 模式：直接对原始数据进行签名（业务层处理格式）
		// 对于 ECDSA，需要先计算摘要
		if req.Algorithm != algorithmED25519 {
			digest = s.computeDigest(req.Message, req.Algorithm)
		}
	} else {
		// DIGEST 模式：对消息摘要进行签名
		digest = s.computeDigest(req.Message, req.Algorithm)
	}

	// 在 HSM 内执行签名
	signature, err := s.hsmAdapter.Sign(ctx, primaryVersion.HSMHandle, digest, req.Algorithm)
	if err != nil {
		return nil, errors.Wrap(err, "failed to sign in HSM")
	}

	// 记录审计日志
	_ = s.auditLogger.LogEvent(ctx, &audit.AuditEvent{
		EventType: "Sign",
		KeyID:     req.KeyID,
		Operation: "sign",
		Result:    "Success",
	})

	return &SignResponse{
		Signature:  signature,
		KeyID:      req.KeyID,
		KeyVersion: primaryVersion.Version,
		Algorithm:  req.Algorithm,
	}, nil
}

// Verify 验证签名
func (s *service) Verify(ctx context.Context, req *VerifyRequest) (*VerifyResponse, error) {
	// 获取密钥元数据
	keyMetadata, err := s.keyService.GetKey(ctx, req.KeyID)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get key metadata")
	}

	// 验证密钥类型
	if keyMetadata.KeyType != key.KeyTypeECCSecp256k1 &&
		keyMetadata.KeyType != key.KeyTypeECCP256 &&
		keyMetadata.KeyType != key.KeyTypeEd25519 {
		return nil, ErrInvalidKeyType
	}

	// 验证算法
	if err := s.validateAlgorithm(keyMetadata.KeyType, req.Algorithm); err != nil {
		return nil, err
	}

	// 获取主版本密钥句柄
	primaryVersion, err := s.metadataStore.GetPrimaryKeyVersion(ctx, req.KeyID)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get primary key version")
	}

	// 处理消息（根据模式）
	digest := req.Message
	if req.Mode == "RAW" {
		// RAW 模式：直接对原始数据进行验证
		// 对于 ECDSA，需要先计算摘要
		if req.Algorithm != algorithmED25519 {
			digest = s.computeDigest(req.Message, req.Algorithm)
		}
	} else {
		// DIGEST 模式：对消息摘要进行验证
		digest = s.computeDigest(req.Message, req.Algorithm)
	}

	// 在 HSM 内执行验证
	// 注意：PKCS#11 的 Verify 需要公钥句柄，这里需要改进
	// 暂时返回错误，后续需要实现公钥查找
	valid, err := s.hsmAdapter.Verify(ctx, primaryVersion.HSMHandle, digest, req.Signature, req.Algorithm)
	if err != nil {
		// 如果验证失败，记录审计日志
		_ = s.auditLogger.LogEvent(ctx, &audit.AuditEvent{
			EventType: "Verify",
			KeyID:     req.KeyID,
			Operation: "verify",
			Result:    "Failure",
		})
		return nil, errors.Wrap(err, "failed to verify signature in HSM")
	}

	// 记录审计日志
	_ = s.auditLogger.LogEvent(ctx, &audit.AuditEvent{
		EventType: "Verify",
		KeyID:     req.KeyID,
		Operation: "verify",
		Result:    "Success",
	})

	return &VerifyResponse{
		Valid:      valid,
		KeyID:      req.KeyID,
		KeyVersion: primaryVersion.Version,
	}, nil
}

// validateAlgorithm 验证签名算法
func (s *service) validateAlgorithm(keyType key.KeyType, algorithm string) error {
	switch keyType {
	case key.KeyTypeECCSecp256k1, key.KeyTypeECCP256:
		switch algorithm {
		case "ECDSA_SHA256", "ECDSA_SHA384", "ECDSA_SHA512":
			return nil
		default:
			return ErrInvalidAlgorithm
		}
	case key.KeyTypeEd25519:
		if algorithm == algorithmED25519 {
			return nil
		}
		return ErrInvalidAlgorithm
	default:
		return ErrInvalidKeyType
	}
}

// computeDigest 计算消息摘要
func (s *service) computeDigest(message []byte, algorithm string) []byte {
	switch algorithm {
	case "ECDSA_SHA256", algorithmED25519:
		hash := sha256.Sum256(message)
		return hash[:]
	case "ECDSA_SHA384":
		hash := sha512.Sum384(message)
		return hash[:]
	case "ECDSA_SHA512":
		hash := sha512.Sum512(message)
		return hash[:]
	default:
		// 默认使用 SHA256
		hash := sha256.Sum256(message)
		return hash[:]
	}
}
