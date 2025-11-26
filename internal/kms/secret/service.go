package secret

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"time"

	"github.com/kashguard/go-kms/internal/kms/audit"
	"github.com/kashguard/go-kms/internal/kms/encryption"
	"github.com/kashguard/go-kms/internal/kms/key"
	"github.com/kashguard/go-kms/internal/kms/policy"
	"github.com/kashguard/go-kms/internal/kms/storage"
	"github.com/pkg/errors"
)

const (
	errSecretNotFound = "secret not found"
)

// Service Secret 存储服务接口
type Service interface {
	CreateSecret(ctx context.Context, keyID string, data []byte) (string, error)
	GetSecret(ctx context.Context, keyID string) ([]byte, error)
	UpdateSecret(ctx context.Context, keyID string, data []byte) error
	DeleteSecret(ctx context.Context, keyID string) error
	SecretExists(ctx context.Context, keyID string) (bool, error)
}

// service Secret 存储服务实现
type service struct {
	encryptionService encryption.Service
	keyService        key.Service
	metadataStore     storage.MetadataStore
	policyEngine      policy.Engine
	auditLogger       audit.Logger
	secretKMSKeyID    string // 全局 KMS 密钥ID，用于加密所有 Secret
}

// NewService 创建新的 Secret 存储服务
//
//nolint:ireturn // returning interface is intentional for abstraction
func NewService(
	encryptionService encryption.Service,
	keyService key.Service,
	metadataStore storage.MetadataStore,
	policyEngine policy.Engine,
	auditLogger audit.Logger,
	secretKMSKeyID string,
) (Service, error) {
	return &service{
		encryptionService: encryptionService,
		keyService:        keyService,
		metadataStore:     metadataStore,
		policyEngine:      policyEngine,
		auditLogger:       auditLogger,
		secretKMSKeyID:    secretKMSKeyID,
	}, nil
}

// CreateSecret 创建 Secret 并存储加密数据
func (s *service) CreateSecret(ctx context.Context, keyID string, data []byte) (string, error) {
	// 检查 Secret 是否已存在
	exists, err := s.metadataStore.SecretExists(ctx, keyID)
	if err != nil {
		return "", errors.Wrap(err, "failed to check secret existence")
	}
	if exists {
		return "", ErrSecretAlreadyExists
	}

	// 验证全局 KMS 密钥是否存在且可用
	kmsKey, err := s.keyService.GetKey(ctx, s.secretKMSKeyID)
	if err != nil {
		return "", errors.Wrap(err, "failed to get secret KMS key")
	}
	if kmsKey.KeyState != key.KeyStateEnabled {
		return "", ErrInvalidKMSKey
	}

	// 验证权限（如果密钥有策略）
	if kmsKey.PolicyID != "" {
		if err := s.policyEngine.EvaluatePolicy(ctx, kmsKey.PolicyID, "use_key"); err != nil {
			return "", errors.Wrap(err, "policy evaluation failed")
		}
	}

	// 使用全局 KMS 密钥加密数据
	encryptReq := &encryption.EncryptRequest{
		KeyID:             s.secretKMSKeyID,
		Plaintext:         data,
		EncryptionContext: map[string]string{"purpose": "secret_storage", "secret_id": keyID},
	}

	encryptResp, err := s.encryptionService.Encrypt(ctx, encryptReq)
	if err != nil {
		return "", errors.Wrap(err, "failed to encrypt secret data")
	}

	// 解析密文 Blob 获取密钥版本
	keyIDFromBlob, keyVersion, _, _, err := s.parseCiphertextBlob(encryptResp.CiphertextBlob)
	if err != nil {
		return "", errors.Wrap(err, "failed to parse ciphertext blob")
	}
	_ = keyIDFromBlob // 验证 keyID 匹配（可选）

	// 保存 Secret 到数据库
	now := time.Now()
	secret := &storage.Secret{
		KeyID:         keyID,
		EncryptedData: encryptResp.CiphertextBlob,
		KMSKeyID:      s.secretKMSKeyID,
		KeyVersion:    keyVersion,
		CreatedAt:     now,
		UpdatedAt:     now,
	}

	if err := s.metadataStore.SaveSecret(ctx, secret); err != nil {
		return "", errors.Wrap(err, "failed to save secret")
	}

	// 记录审计日志
	_ = s.auditLogger.LogEvent(ctx, &audit.AuditEvent{
		EventType: "SecretCreated",
		KeyID:     keyID,
		Operation: "create_secret",
		Result:    "Success",
	})

	return keyID, nil
}

// GetSecret 获取并解密 Secret 数据
func (s *service) GetSecret(ctx context.Context, keyID string) ([]byte, error) {
	// 从数据库获取 Secret
	secret, err := s.metadataStore.GetSecret(ctx, keyID)
	if err != nil {
		if err.Error() == errSecretNotFound {
			return nil, ErrSecretNotFound
		}
		return nil, errors.Wrap(err, "failed to get secret")
	}

	// 验证 KMS 密钥是否存在且可用
	kmsKey, err := s.keyService.GetKey(ctx, secret.KMSKeyID)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get secret KMS key")
	}
	if kmsKey.KeyState == key.KeyStateDeleted {
		return nil, ErrInvalidKMSKey
	}

	// 验证权限（如果密钥有策略）
	if kmsKey.PolicyID != "" {
		if err := s.policyEngine.EvaluatePolicy(ctx, kmsKey.PolicyID, "use_key"); err != nil {
			return nil, errors.Wrap(err, "policy evaluation failed")
		}
	}

	// 使用 KMS 密钥解密数据
	decryptReq := &encryption.DecryptRequest{
		CiphertextBlob:    secret.EncryptedData,
		EncryptionContext: map[string]string{"purpose": "secret_storage", "secret_id": keyID},
	}

	decryptResp, err := s.encryptionService.Decrypt(ctx, decryptReq)
	if err != nil {
		return nil, errors.Wrap(err, "failed to decrypt secret data")
	}

	// 记录审计日志
	_ = s.auditLogger.LogEvent(ctx, &audit.AuditEvent{
		EventType: "SecretAccessed",
		KeyID:     keyID,
		Operation: "get_secret",
		Result:    "Success",
	})

	return decryptResp.Plaintext, nil
}

// UpdateSecret 更新 Secret 数据
func (s *service) UpdateSecret(ctx context.Context, keyID string, data []byte) error {
	// 检查 Secret 是否存在
	existingSecret, err := s.metadataStore.GetSecret(ctx, keyID)
	if err != nil {
		if err.Error() == errSecretNotFound {
			return ErrSecretNotFound
		}
		return errors.Wrap(err, "failed to get secret for update")
	}

	// 验证全局 KMS 密钥是否存在且可用
	kmsKey, err := s.keyService.GetKey(ctx, s.secretKMSKeyID)
	if err != nil {
		return errors.Wrap(err, "failed to get secret KMS key")
	}
	if kmsKey.KeyState != key.KeyStateEnabled {
		return ErrInvalidKMSKey
	}

	// 验证权限（如果密钥有策略）
	if kmsKey.PolicyID != "" {
		if err := s.policyEngine.EvaluatePolicy(ctx, kmsKey.PolicyID, "use_key"); err != nil {
			return errors.Wrap(err, "policy evaluation failed")
		}
	}

	// 使用全局 KMS 密钥加密新数据
	encryptReq := &encryption.EncryptRequest{
		KeyID:             s.secretKMSKeyID,
		Plaintext:         data,
		EncryptionContext: map[string]string{"purpose": "secret_storage", "secret_id": keyID},
	}

	encryptResp, err := s.encryptionService.Encrypt(ctx, encryptReq)
	if err != nil {
		return errors.Wrap(err, "failed to encrypt secret data")
	}

	// 解析密文 Blob 获取密钥版本
	keyIDFromBlob, keyVersion, _, _, err := s.parseCiphertextBlob(encryptResp.CiphertextBlob)
	if err != nil {
		return errors.Wrap(err, "failed to parse ciphertext blob")
	}
	_ = keyIDFromBlob // 验证 keyID 匹配（可选）

	// 更新 Secret
	updatedSecret := &storage.Secret{
		KeyID:         keyID,
		EncryptedData: encryptResp.CiphertextBlob,
		KMSKeyID:      s.secretKMSKeyID,
		KeyVersion:    keyVersion,
		CreatedAt:     existingSecret.CreatedAt,
		UpdatedAt:     time.Now(),
	}

	if err := s.metadataStore.UpdateSecret(ctx, keyID, updatedSecret); err != nil {
		return errors.Wrap(err, "failed to update secret")
	}

	// 记录审计日志
	_ = s.auditLogger.LogEvent(ctx, &audit.AuditEvent{
		EventType: "SecretUpdated",
		KeyID:     keyID,
		Operation: "update_secret",
		Result:    "Success",
	})

	return nil
}

// DeleteSecret 删除 Secret
func (s *service) DeleteSecret(ctx context.Context, keyID string) error {
	// 检查 Secret 是否存在
	_, err := s.metadataStore.GetSecret(ctx, keyID)
	if err != nil {
		if err.Error() == errSecretNotFound {
			return ErrSecretNotFound
		}
		return errors.Wrap(err, "failed to get secret for deletion")
	}

	// 删除 Secret
	if err := s.metadataStore.DeleteSecret(ctx, keyID); err != nil {
		return errors.Wrap(err, "failed to delete secret")
	}

	// 记录审计日志
	_ = s.auditLogger.LogEvent(ctx, &audit.AuditEvent{
		EventType: "SecretDeleted",
		KeyID:     keyID,
		Operation: "delete_secret",
		Result:    "Success",
	})

	return nil
}

// SecretExists 检查 Secret 是否存在
func (s *service) SecretExists(ctx context.Context, keyID string) (bool, error) {
	return s.metadataStore.SecretExists(ctx, keyID)
}

// parseCiphertextBlob 解析密文 Blob（复用 encryption service 的逻辑）
//
//nolint:nonamedreturns,unparam // named returns are used for clarity; keyID is part of the interface signature
func (s *service) parseCiphertextBlob(blob []byte) (keyID string, version int, ciphertext []byte, encryptionContext map[string]string, err error) {
	var data map[string]interface{}
	if err := json.Unmarshal(blob, &data); err != nil {
		return "", 0, nil, nil, errors.Wrap(err, "failed to unmarshal ciphertext blob")
	}

	// 提取 key_id
	if keyIDStr, ok := data["key_id"].(string); ok {
		keyID = keyIDStr
	} else {
		return "", 0, nil, nil, errors.New("missing key_id in ciphertext blob")
	}

	// 提取 version
	if versionFloat, ok := data["version"].(float64); ok {
		version = int(versionFloat)
	}

	// 提取 ciphertext
	if ciphertextStr, ok := data["ciphertext"].(string); ok {
		ciphertext, err = base64.StdEncoding.DecodeString(ciphertextStr)
		if err != nil {
			return "", 0, nil, nil, errors.Wrap(err, "failed to decode ciphertext")
		}
	} else {
		return "", 0, nil, nil, errors.New("missing ciphertext in ciphertext blob")
	}

	// 提取 encryption_context（可选）
	if ctxData, ok := data["encryption_context"].(map[string]interface{}); ok {
		encryptionContext = make(map[string]string)
		for k, v := range ctxData {
			if vStr, ok := v.(string); ok {
				encryptionContext[k] = vStr
			}
		}
	}

	return keyID, version, ciphertext, encryptionContext, nil
}
