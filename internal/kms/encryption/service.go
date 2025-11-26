package encryption

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"

	"github.com/kashguard/go-kms/internal/kms/audit"
	"github.com/kashguard/go-kms/internal/kms/hsm"
	"github.com/kashguard/go-kms/internal/kms/key"
	"github.com/kashguard/go-kms/internal/kms/policy"
	"github.com/kashguard/go-kms/internal/kms/storage"
	"github.com/pkg/errors"
)

var (
	ErrKeyNotFound       = errors.New("key not found")
	ErrKeyDisabled       = errors.New("key is disabled")
	ErrInvalidCiphertext = errors.New("invalid ciphertext")
	ErrInvalidKeyType    = errors.New("invalid key type for encryption")
)

// Service 加密解密服务接口
type Service interface {
	Encrypt(ctx context.Context, req *EncryptRequest) (*EncryptResponse, error)
	Decrypt(ctx context.Context, req *DecryptRequest) (*DecryptResponse, error)
	GenerateDataKey(ctx context.Context, req *GenerateDataKeyRequest) (*GenerateDataKeyResponse, error)
}

// service 加密解密服务实现
type service struct {
	keyService    key.Service
	hsmAdapter    hsm.Adapter
	metadataStore storage.MetadataStore
	policyEngine  policy.Engine
	auditLogger   audit.Logger
}

// NewService 创建新的加密解密服务
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

// Encrypt 加密数据
func (s *service) Encrypt(ctx context.Context, req *EncryptRequest) (*EncryptResponse, error) {
	// 获取密钥元数据
	keyMetadata, err := s.keyService.GetKey(ctx, req.KeyID)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get key metadata")
	}

	// 验证密钥状态
	if keyMetadata.KeyState != key.KeyStateEnabled {
		return nil, ErrKeyDisabled
	}

	// 验证密钥类型（只支持对称密钥加密）
	if keyMetadata.KeyType != key.KeyTypeAES256 {
		return nil, ErrInvalidKeyType
	}

	// 验证权限
	if keyMetadata.PolicyID != "" {
		if err := s.policyEngine.EvaluatePolicy(ctx, keyMetadata.PolicyID, "use_key"); err != nil {
			return nil, errors.Wrap(err, "policy evaluation failed")
		}
	}

	// 验证加密上下文
	if err := s.validateEncryptionContext(req.EncryptionContext); err != nil {
		return nil, errors.Wrap(err, "encryption context validation failed")
	}

	// 获取主版本密钥句柄
	primaryVersion, err := s.metadataStore.GetPrimaryKeyVersion(ctx, req.KeyID)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get primary key version")
	}

	// 在 HSM 内执行加密
	ciphertext, err := s.hsmAdapter.Encrypt(ctx, primaryVersion.HSMHandle, req.Plaintext)
	if err != nil {
		return nil, errors.Wrap(err, "failed to encrypt in HSM")
	}

	// 构建密文 Blob（包含密钥ID、版本和加密上下文）
	ciphertextBlob := s.buildCiphertextBlob(req.KeyID, primaryVersion.Version, ciphertext, req.EncryptionContext)

	// 记录审计日志
	_ = s.auditLogger.LogEvent(ctx, &audit.AuditEvent{
		EventType: "Encrypt",
		KeyID:     req.KeyID,
		Operation: "encrypt",
		Result:    "Success",
	})

	return &EncryptResponse{
		CiphertextBlob: ciphertextBlob,
		KeyID:          req.KeyID,
		KeyVersion:     primaryVersion.Version,
	}, nil
}

// Decrypt 解密数据
func (s *service) Decrypt(ctx context.Context, req *DecryptRequest) (*DecryptResponse, error) {
	// 解析密文 Blob
	keyID, version, ciphertext, encryptionContext, err := s.parseCiphertextBlob(req.CiphertextBlob)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse ciphertext blob")
	}

	// 获取密钥元数据
	keyMetadata, err := s.keyService.GetKey(ctx, keyID)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get key metadata")
	}

	// 验证密钥状态（允许 Disabled 状态的密钥用于解密历史数据）
	if keyMetadata.KeyState == key.KeyStateDeleted {
		return nil, errors.New("key is deleted")
	}

	// 验证权限
	if keyMetadata.PolicyID != "" {
		if err := s.policyEngine.EvaluatePolicy(ctx, keyMetadata.PolicyID, "use_key"); err != nil {
			return nil, errors.Wrap(err, "policy evaluation failed")
		}
	}

	// 验证加密上下文（如果提供）
	if req.EncryptionContext != nil {
		if !s.matchEncryptionContext(encryptionContext, req.EncryptionContext) {
			return nil, errors.New("encryption context mismatch")
		}
	}

	// 获取指定版本的密钥句柄
	var hsmHandle string
	if version > 0 {
		keyVersion, err := s.metadataStore.GetKeyVersion(ctx, keyID, version)
		if err != nil {
			return nil, errors.Wrap(err, "failed to get key version")
		}
		hsmHandle = keyVersion.HSMHandle
	} else {
		// 使用主版本
		primaryVersion, err := s.metadataStore.GetPrimaryKeyVersion(ctx, keyID)
		if err != nil {
			return nil, errors.Wrap(err, "failed to get primary key version")
		}
		hsmHandle = primaryVersion.HSMHandle
		version = primaryVersion.Version
	}

	// 在 HSM 内执行解密
	plaintext, err := s.hsmAdapter.Decrypt(ctx, hsmHandle, ciphertext)
	if err != nil {
		return nil, errors.Wrap(err, "failed to decrypt in HSM")
	}

	// 记录审计日志
	_ = s.auditLogger.LogEvent(ctx, &audit.AuditEvent{
		EventType: "Decrypt",
		KeyID:     keyID,
		Operation: "decrypt",
		Result:    "Success",
	})

	return &DecryptResponse{
		Plaintext:  plaintext,
		KeyID:      keyID,
		KeyVersion: version,
	}, nil
}

// GenerateDataKey 生成数据密钥（信封加密）
func (s *service) GenerateDataKey(ctx context.Context, req *GenerateDataKeyRequest) (*GenerateDataKeyResponse, error) {
	// 获取密钥元数据
	keyMetadata, err := s.keyService.GetKey(ctx, req.KeyID)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get key metadata")
	}

	// 验证密钥状态
	if keyMetadata.KeyState != key.KeyStateEnabled {
		return nil, ErrKeyDisabled
	}

	// 验证权限
	if keyMetadata.PolicyID != "" {
		if err := s.policyEngine.EvaluatePolicy(ctx, keyMetadata.PolicyID, "use_key"); err != nil {
			return nil, errors.Wrap(err, "policy evaluation failed")
		}
	}

	// 生成数据加密密钥（DEK）
	keySize := req.NumberOfBytes
	if keySize <= 0 {
		keySize = 32 // 默认 32 字节（256 位）
	}

	dek := make([]byte, keySize)
	if _, err := rand.Read(dek); err != nil {
		return nil, errors.Wrap(err, "failed to generate random DEK")
	}

	// 获取主版本密钥句柄
	primaryVersion, err := s.metadataStore.GetPrimaryKeyVersion(ctx, req.KeyID)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get primary key version")
	}

	// 使用 KMS 密钥加密 DEK（生成 KEK）
	kek, err := s.hsmAdapter.Encrypt(ctx, primaryVersion.HSMHandle, dek)
	if err != nil {
		return nil, errors.Wrap(err, "failed to encrypt DEK")
	}

	// 构建密文 Blob
	ciphertextBlob := s.buildCiphertextBlob(req.KeyID, primaryVersion.Version, kek, req.EncryptionContext)

	response := &GenerateDataKeyResponse{
		CiphertextBlob: ciphertextBlob,
		KeyID:          req.KeyID,
	}

	// 如果请求返回明文，则包含明文 DEK
	if req.ReturnPlaintext {
		response.Plaintext = dek
	}

	// 记录审计日志
	_ = s.auditLogger.LogEvent(ctx, &audit.AuditEvent{
		EventType: "GenerateDataKey",
		KeyID:     req.KeyID,
		Operation: "generate_data_key",
		Result:    "Success",
	})

	return response, nil
}

// validateEncryptionContext 验证加密上下文
func (s *service) validateEncryptionContext(ctx map[string]string) error {
	if ctx == nil {
		return nil
	}

	if len(ctx) > 10 { //nolint:mnd // maximum encryption context pairs
		return errors.New("encryption context too large")
	}

	for key, value := range ctx {
		if len(key) > 128 || len(value) > 1024 {
			return errors.New("encryption context key or value too long")
		}
	}

	return nil
}

// matchEncryptionContext 匹配加密上下文
func (s *service) matchEncryptionContext(ctx1, ctx2 map[string]string) bool {
	if len(ctx1) != len(ctx2) {
		return false
	}

	for k, v1 := range ctx1 {
		if v2, ok := ctx2[k]; !ok || v1 != v2 {
			return false
		}
	}

	return true
}

// buildCiphertextBlob 构建密文 Blob
// 格式：JSON 包含 key_id, version, ciphertext, encryption_context
func (s *service) buildCiphertextBlob(keyID string, version int, ciphertext []byte, encryptionContext map[string]string) []byte {
	blob := map[string]interface{}{
		"key_id":     keyID,
		"version":    version,
		"ciphertext": base64.StdEncoding.EncodeToString(ciphertext),
	}

	if encryptionContext != nil {
		blob["encryption_context"] = encryptionContext
	}

	jsonData, err := json.Marshal(blob)
	if err != nil {
		// 如果 marshal 失败，返回空字节数组（这种情况不应该发生，因为 blob 是 map[string]interface{}）
		return []byte{}
	}
	return jsonData
}

// parseCiphertextBlob 解析密文 Blob
//
//nolint:nonamedreturns // named returns are used for clarity
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
