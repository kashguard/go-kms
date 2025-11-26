package key

import (
	"context"
	"database/sql"
	"time"

	"github.com/google/uuid"
	"github.com/kashguard/go-kms/internal/kms/audit"
	"github.com/kashguard/go-kms/internal/kms/hsm"
	"github.com/kashguard/go-kms/internal/kms/policy"
	"github.com/kashguard/go-kms/internal/kms/storage"
	"github.com/pkg/errors"
)

var (
	ErrKeyNotFound     = errors.New("key not found")
	ErrInvalidKeyType  = errors.New("invalid key type")
	ErrInvalidKeyState = errors.New("invalid key state")
	ErrKeyDisabled     = errors.New("key is disabled")
	ErrKeyDeleted      = errors.New("key is deleted")
	ErrPolicyDenied    = errors.New("policy denied")
)

// Service 密钥管理服务接口
type Service interface {
	CreateKey(ctx context.Context, req *CreateKeyRequest) (*KeyMetadata, error)
	GetKey(ctx context.Context, keyID string) (*KeyMetadata, error)
	UpdateKey(ctx context.Context, keyID string, req *UpdateKeyRequest) error
	DeleteKey(ctx context.Context, keyID string) error
	EnableKey(ctx context.Context, keyID string) error
	DisableKey(ctx context.Context, keyID string) error
	RotateKey(ctx context.Context, keyID string) (*KeyMetadata, error)
	ListKeys(ctx context.Context, filter *KeyFilter) ([]*KeyMetadata, error)
}

// service 密钥管理服务实现
type service struct {
	db            *sql.DB
	hsmAdapter    hsm.Adapter
	metadataStore storage.MetadataStore
	policyEngine  policy.Engine
	auditLogger   audit.Logger
}

// NewService 创建新的密钥管理服务
//
//nolint:ireturn // returning interface is intentional for abstraction
func NewService(
	db *sql.DB,
	hsmAdapter hsm.Adapter,
	metadataStore storage.MetadataStore,
	policyEngine policy.Engine,
	auditLogger audit.Logger,
) (Service, error) {
	return &service{
		db:            db,
		hsmAdapter:    hsmAdapter,
		metadataStore: metadataStore,
		policyEngine:  policyEngine,
		auditLogger:   auditLogger,
	}, nil
}

// CreateKey 创建密钥
func (s *service) CreateKey(ctx context.Context, req *CreateKeyRequest) (*KeyMetadata, error) {
	// 验证密钥类型
	if !s.isValidKeyType(req.KeyType) {
		return nil, ErrInvalidKeyType
	}

	// 验证权限（如果提供了策略ID）
	if req.PolicyID != "" {
		if err := s.policyEngine.EvaluatePolicy(ctx, req.PolicyID, "create_key"); err != nil {
			return nil, errors.Wrap(err, "policy evaluation failed")
		}
	}

	// 生成密钥ID
	keyID := s.generateKeyID()

	// 构建密钥规格
	keySpec := s.buildKeySpec(req.KeyType, req.KeySpec)

	// 在 HSM 内生成密钥
	hsmHandle, err := s.hsmAdapter.GenerateKey(ctx, keySpec)
	if err != nil {
		return nil, errors.Wrap(err, "failed to generate key in HSM")
	}

	now := time.Now()

	// 保存密钥元数据
	keyMetadata := &storage.KeyMetadata{
		KeyID:       keyID,
		Alias:       req.Alias,
		Description: req.Description,
		KeyType:     string(req.KeyType),
		KeyState:    string(KeyStateEnabled),
		HSMHandle:   hsmHandle,
		PolicyID:    req.PolicyID,
		CreatedAt:   now,
		UpdatedAt:   now,
		Tags:        req.Tags,
	}

	// 转换 KeySpec 为 map
	if req.KeySpec != nil {
		keyMetadata.KeySpec = map[string]interface{}{
			"algorithm": req.KeySpec.Algorithm,
			"key_size":  req.KeySpec.KeySize,
		}
		if req.KeySpec.Curve != "" {
			keyMetadata.KeySpec["curve"] = req.KeySpec.Curve
		}
		if req.KeySpec.Attributes != nil {
			keyMetadata.KeySpec["attributes"] = req.KeySpec.Attributes
		}
	}

	if err := s.metadataStore.SaveKeyMetadata(ctx, keyMetadata); err != nil {
		// 如果保存失败，尝试删除 HSM 中的密钥
		_ = s.hsmAdapter.DeleteKey(ctx, hsmHandle)
		return nil, errors.Wrap(err, "failed to save key metadata")
	}

	// 创建初始版本记录
	keyVersion := &storage.KeyVersion{
		KeyID:     keyID,
		Version:   1,
		HSMHandle: hsmHandle,
		IsPrimary: true,
		CreatedAt: now,
	}

	if err := s.metadataStore.SaveKeyVersion(ctx, keyVersion); err != nil {
		// 如果保存版本失败，删除元数据
		_ = s.metadataStore.DeleteKeyMetadata(ctx, keyID)
		_ = s.hsmAdapter.DeleteKey(ctx, hsmHandle)
		return nil, errors.Wrap(err, "failed to save key version")
	}

	// 记录审计日志
	_ = s.auditLogger.LogEvent(ctx, &audit.AuditEvent{
		EventType: "KeyCreated",
		KeyID:     keyID,
		Operation: "create_key",
		Result:    "Success",
	})

	// 转换为服务内部类型
	return s.storageToKeyMetadata(keyMetadata, 1), nil
}

// GetKey 获取密钥
func (s *service) GetKey(ctx context.Context, keyID string) (*KeyMetadata, error) {
	keyMetadata, err := s.metadataStore.GetKeyMetadata(ctx, keyID)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get key metadata")
	}

	// 获取最新版本号
	versions, err := s.metadataStore.ListKeyVersions(ctx, keyID)
	if err != nil {
		return nil, errors.Wrap(err, "failed to list key versions")
	}

	latestVersion := 0
	if len(versions) > 0 {
		latestVersion = versions[0].Version
	}

	return s.storageToKeyMetadata(keyMetadata, latestVersion), nil
}

// UpdateKey 更新密钥
func (s *service) UpdateKey(ctx context.Context, keyID string, req *UpdateKeyRequest) error {
	// 获取密钥元数据
	keyMetadata, err := s.metadataStore.GetKeyMetadata(ctx, keyID)
	if err != nil {
		return errors.Wrap(err, "failed to get key metadata")
	}

	// 验证权限
	if keyMetadata.PolicyID != "" {
		if err := s.policyEngine.EvaluatePolicy(ctx, keyMetadata.PolicyID, "update_key"); err != nil {
			return errors.Wrap(err, "policy evaluation failed")
		}
	}

	// 构建更新映射
	updates := make(map[string]interface{})
	if req.Description != "" {
		updates["description"] = req.Description
	}
	if req.PolicyID != "" {
		updates["policy_id"] = req.PolicyID
	}
	if req.Tags != nil {
		updates["tags"] = req.Tags
	}
	if req.DeletionDate != nil {
		updates["deletion_date"] = req.DeletionDate
	}

	if err := s.metadataStore.UpdateKeyMetadata(ctx, keyID, updates); err != nil {
		return errors.Wrap(err, "failed to update key metadata")
	}

	// 记录审计日志
	_ = s.auditLogger.LogEvent(ctx, &audit.AuditEvent{
		EventType: "KeyUpdated",
		KeyID:     keyID,
		Operation: "update_key",
		Result:    "Success",
	})

	return nil
}

// DeleteKey 删除密钥（计划删除）
func (s *service) DeleteKey(ctx context.Context, keyID string) error {
	// 获取密钥元数据
	keyMetadata, err := s.metadataStore.GetKeyMetadata(ctx, keyID)
	if err != nil {
		return errors.Wrap(err, "failed to get key metadata")
	}

	// 验证权限
	if keyMetadata.PolicyID != "" {
		if err := s.policyEngine.EvaluatePolicy(ctx, keyMetadata.PolicyID, "delete_key"); err != nil {
			return errors.Wrap(err, "policy evaluation failed")
		}
	}

	// 设置删除日期（默认 30 天后）
	deletionDate := time.Now().Add(30 * 24 * time.Hour)
	updates := map[string]interface{}{
		"key_state":     string(KeyStatePendingDeletion),
		"deletion_date": &deletionDate,
	}

	if err := s.metadataStore.UpdateKeyMetadata(ctx, keyID, updates); err != nil {
		return errors.Wrap(err, "failed to update key metadata")
	}

	// 记录审计日志
	_ = s.auditLogger.LogEvent(ctx, &audit.AuditEvent{
		EventType: "KeyDeleted",
		KeyID:     keyID,
		Operation: "delete_key",
		Result:    "Success",
	})

	return nil
}

// EnableKey 启用密钥
func (s *service) EnableKey(ctx context.Context, keyID string) error {
	keyMetadata, err := s.metadataStore.GetKeyMetadata(ctx, keyID)
	if err != nil {
		return errors.Wrap(err, "failed to get key metadata")
	}

	if keyMetadata.KeyState == string(KeyStateDeleted) {
		return ErrKeyDeleted
	}

	updates := map[string]interface{}{
		"key_state": string(KeyStateEnabled),
	}

	if err := s.metadataStore.UpdateKeyMetadata(ctx, keyID, updates); err != nil {
		return errors.Wrap(err, "failed to update key metadata")
	}

	// 记录审计日志
	_ = s.auditLogger.LogEvent(ctx, &audit.AuditEvent{
		EventType: "KeyStateChanged",
		KeyID:     keyID,
		Operation: "enable_key",
		Result:    "Success",
	})

	return nil
}

// DisableKey 禁用密钥
func (s *service) DisableKey(ctx context.Context, keyID string) error {
	keyMetadata, err := s.metadataStore.GetKeyMetadata(ctx, keyID)
	if err != nil {
		return errors.Wrap(err, "failed to get key metadata")
	}

	if keyMetadata.KeyState == string(KeyStateDeleted) {
		return ErrKeyDeleted
	}

	updates := map[string]interface{}{
		"key_state": string(KeyStateDisabled),
	}

	if err := s.metadataStore.UpdateKeyMetadata(ctx, keyID, updates); err != nil {
		return errors.Wrap(err, "failed to update key metadata")
	}

	// 记录审计日志
	_ = s.auditLogger.LogEvent(ctx, &audit.AuditEvent{
		EventType: "KeyStateChanged",
		KeyID:     keyID,
		Operation: "disable_key",
		Result:    "Success",
	})

	return nil
}

// RotateKey 轮换密钥
func (s *service) RotateKey(ctx context.Context, keyID string) (*KeyMetadata, error) {
	// 获取当前密钥
	keyMetadata, err := s.metadataStore.GetKeyMetadata(ctx, keyID)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get key metadata")
	}

	// 验证权限
	if keyMetadata.PolicyID != "" {
		if err := s.policyEngine.EvaluatePolicy(ctx, keyMetadata.PolicyID, "rotate_key"); err != nil {
			return nil, errors.Wrap(err, "policy evaluation failed")
		}
	}

	// 获取当前主版本
	primaryVersion, err := s.metadataStore.GetPrimaryKeyVersion(ctx, keyID)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get primary key version")
	}

	// 获取所有版本以确定新版本号
	versions, err := s.metadataStore.ListKeyVersions(ctx, keyID)
	if err != nil {
		return nil, errors.Wrap(err, "failed to list key versions")
	}

	newVersion := 1
	if len(versions) > 0 {
		newVersion = versions[0].Version + 1
	}

	// 构建密钥规格
	keySpec := s.buildKeySpecFromMetadata(keyMetadata)

	// 在 HSM 内生成新版本密钥
	newHandle, err := s.hsmAdapter.GenerateKey(ctx, keySpec)
	if err != nil {
		return nil, errors.Wrap(err, "failed to generate new key version")
	}

	// 更新旧版本为非主版本
	if err := s.metadataStore.UpdateKeyVersionPrimary(ctx, keyID, primaryVersion.Version, false); err != nil {
		return nil, errors.Wrap(err, "failed to update old version")
	}

	// 创建新版本记录
	newVersionRecord := &storage.KeyVersion{
		KeyID:     keyID,
		Version:   newVersion,
		HSMHandle: newHandle,
		IsPrimary: true,
		CreatedAt: time.Now(),
	}

	if err := s.metadataStore.SaveKeyVersion(ctx, newVersionRecord); err != nil {
		// 如果保存失败，删除 HSM 中的新密钥
		_ = s.hsmAdapter.DeleteKey(ctx, newHandle)
		return nil, errors.Wrap(err, "failed to save new version")
	}

	// 更新密钥元数据的 HSM 句柄
	updates := map[string]interface{}{
		"hsm_handle": newHandle,
	}
	if err := s.metadataStore.UpdateKeyMetadata(ctx, keyID, updates); err != nil {
		return nil, errors.Wrap(err, "failed to update key metadata")
	}

	// 记录审计日志
	_ = s.auditLogger.LogEvent(ctx, &audit.AuditEvent{
		EventType: "KeyRotated",
		KeyID:     keyID,
		Operation: "rotate_key",
		Result:    "Success",
	})

	// 获取更新后的密钥元数据
	updatedMetadata, err := s.metadataStore.GetKeyMetadata(ctx, keyID)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get updated key metadata")
	}

	return s.storageToKeyMetadata(updatedMetadata, newVersion), nil
}

// ListKeys 列出密钥
func (s *service) ListKeys(ctx context.Context, filter *KeyFilter) ([]*KeyMetadata, error) {
	storageFilter := &storage.KeyFilter{
		State:   filter.State,
		KeyType: filter.KeyType,
		Alias:   filter.Alias,
		Tags:    filter.Tags,
		Limit:   filter.Limit,
		Offset:  filter.Offset,
	}

	storageKeys, err := s.metadataStore.ListKeyMetadata(ctx, storageFilter)
	if err != nil {
		return nil, errors.Wrap(err, "failed to list key metadata")
	}

	result := make([]*KeyMetadata, 0, len(storageKeys))
	for _, storageKey := range storageKeys {
		// 获取最新版本号
		versions, err := s.metadataStore.ListKeyVersions(ctx, storageKey.KeyID)
		if err != nil {
			continue // 跳过无法获取版本的密钥
		}

		latestVersion := 0
		if len(versions) > 0 {
			latestVersion = versions[0].Version
		}

		result = append(result, s.storageToKeyMetadata(storageKey, latestVersion))
	}

	return result, nil
}

// isValidKeyType 验证密钥类型是否有效
func (s *service) isValidKeyType(keyType KeyType) bool {
	switch keyType {
	case KeyTypeECCSecp256k1, KeyTypeECCP256, KeyTypeEd25519, KeyTypeAES256:
		return true
	default:
		return false
	}
}

// buildKeySpec 构建密钥规格
func (s *service) buildKeySpec(keyType KeyType, reqSpec *KeySpec) *hsm.KeySpec {
	spec := &hsm.KeySpec{
		KeyType:    string(keyType),
		Attributes: make(map[string]string),
	}

	if reqSpec != nil {
		spec.Algorithm = reqSpec.Algorithm
		spec.KeySize = reqSpec.KeySize
		if reqSpec.Curve != "" {
			spec.Attributes["curve"] = reqSpec.Curve
		}
		if reqSpec.Attributes != nil {
			for k, v := range reqSpec.Attributes {
				spec.Attributes[k] = v
			}
		}
	} else {
		// 设置默认值
		switch keyType {
		case KeyTypeECCSecp256k1:
			spec.Algorithm = "ECDSA"
			spec.KeySize = 256
			spec.Attributes["curve"] = "secp256k1"
		case KeyTypeECCP256:
			spec.Algorithm = "ECDSA"
			spec.KeySize = 256
			spec.Attributes["curve"] = "P-256"
		case KeyTypeEd25519:
			spec.Algorithm = "EdDSA"
			spec.KeySize = 256
		case KeyTypeAES256:
			spec.Algorithm = "AES"
			spec.KeySize = 256
		}
	}

	return spec
}

// buildKeySpecFromMetadata 从元数据构建密钥规格
func (s *service) buildKeySpecFromMetadata(keyMetadata *storage.KeyMetadata) *hsm.KeySpec {
	spec := &hsm.KeySpec{
		KeyType:    keyMetadata.KeyType,
		Attributes: make(map[string]string),
	}

	//nolint:nestif // KeySpec conversion requires nested conditionals
	if keyMetadata.KeySpec != nil {
		if algorithm, ok := keyMetadata.KeySpec["algorithm"].(string); ok {
			spec.Algorithm = algorithm
		}
		if keySize, ok := keyMetadata.KeySpec["key_size"].(float64); ok {
			spec.KeySize = int(keySize)
		}
		if curve, ok := keyMetadata.KeySpec["curve"].(string); ok {
			spec.Attributes["curve"] = curve
		}
		if attrs, ok := keyMetadata.KeySpec["attributes"].(map[string]interface{}); ok {
			for k, v := range attrs {
				if str, ok := v.(string); ok {
					spec.Attributes[k] = str
				}
			}
		}
	}

	return spec
}

// storageToKeyMetadata 将存储层类型转换为服务层类型
func (s *service) storageToKeyMetadata(storageKey *storage.KeyMetadata, latestVersion int) *KeyMetadata {
	var keySpec *KeySpec
	//nolint:nestif // KeySpec conversion requires nested conditionals
	if storageKey.KeySpec != nil {
		keySpec = &KeySpec{}
		if algorithm, ok := storageKey.KeySpec["algorithm"].(string); ok {
			keySpec.Algorithm = algorithm
		}
		if keySize, ok := storageKey.KeySpec["key_size"].(float64); ok {
			keySpec.KeySize = int(keySize)
		}
		if curve, ok := storageKey.KeySpec["curve"].(string); ok {
			keySpec.Curve = curve
		}
		if attrs, ok := storageKey.KeySpec["attributes"].(map[string]interface{}); ok {
			keySpec.Attributes = make(map[string]string)
			for k, v := range attrs {
				if str, ok := v.(string); ok {
					keySpec.Attributes[k] = str
				}
			}
		}
	}

	return &KeyMetadata{
		KeyID:         storageKey.KeyID,
		Alias:         storageKey.Alias,
		Description:   storageKey.Description,
		KeyType:       KeyType(storageKey.KeyType),
		KeyState:      KeyState(storageKey.KeyState),
		KeySpec:       keySpec,
		HSMHandle:     storageKey.HSMHandle,
		PolicyID:      storageKey.PolicyID,
		CreatedAt:     storageKey.CreatedAt,
		UpdatedAt:     storageKey.UpdatedAt,
		DeletionDate:  storageKey.DeletionDate,
		Tags:          storageKey.Tags,
		LatestVersion: latestVersion,
	}
}

// generateKeyID 生成密钥ID
func (s *service) generateKeyID() string {
	return "key-" + uuid.New().String()
}
