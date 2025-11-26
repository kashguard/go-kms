package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"github.com/aarondl/null/v8"
	"github.com/aarondl/sqlboiler/v4/boil"
	"github.com/aarondl/sqlboiler/v4/queries/qm"
	"github.com/aarondl/sqlboiler/v4/types"
	"github.com/kashguard/go-kms/internal/models"
	"github.com/pkg/errors"
)

// postgresqlStore 实现 PostgreSQL 存储后端
type postgresqlStore struct {
	db *sql.DB
}

// NewPostgreSQLStore 创建新的 PostgreSQL 存储后端
//
//nolint:ireturn // returning interface is intentional for abstraction
func NewPostgreSQLStore(db *sql.DB) MetadataStore {
	return &postgresqlStore{db: db}
}

// SaveKeyMetadata 保存密钥元数据
func (s *postgresqlStore) SaveKeyMetadata(ctx context.Context, key *KeyMetadata) error {
	keyModel := &models.Key{
		KeyID:     key.KeyID,
		KeyType:   key.KeyType,
		KeyState:  key.KeyState,
		HSMHandle: key.HSMHandle,
		CreatedAt: key.CreatedAt,
		UpdatedAt: key.UpdatedAt,
	}

	if key.Alias != "" {
		keyModel.Alias = null.StringFrom(key.Alias)
	}
	if key.Description != "" {
		keyModel.Description = null.StringFrom(key.Description)
	}
	if key.PolicyID != "" {
		keyModel.PolicyID = null.StringFrom(key.PolicyID)
	}

	if key.DeletionDate != nil {
		keyModel.DeletionDate = null.TimeFrom(*key.DeletionDate)
	}

	// 处理 JSONB 字段
	if key.KeySpec != nil {
		keySpecJSON, err := json.Marshal(key.KeySpec)
		if err != nil {
			return errors.Wrap(err, "failed to marshal key_spec")
		}
		keyModel.KeySpec = null.JSONFrom(keySpecJSON)
	}

	if key.Tags != nil {
		tagsJSON, err := json.Marshal(key.Tags)
		if err != nil {
			return errors.Wrap(err, "failed to marshal tags")
		}
		keyModel.Tags = null.JSONFrom(tagsJSON)
	}

	if err := keyModel.Insert(ctx, s.db, boil.Infer()); err != nil {
		return errors.Wrap(err, "failed to insert key metadata")
	}

	return nil
}

// GetKeyMetadata 获取密钥元数据
func (s *postgresqlStore) GetKeyMetadata(ctx context.Context, keyID string) (*KeyMetadata, error) {
	keyModel, err := models.Keys(
		models.KeyWhere.KeyID.EQ(keyID),
	).One(ctx, s.db)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, errors.New("key not found")
		}
		return nil, errors.Wrap(err, "failed to get key metadata")
	}

	return s.keyModelToMetadata(keyModel), nil
}

// UpdateKeyMetadata 更新密钥元数据
func (s *postgresqlStore) UpdateKeyMetadata(ctx context.Context, keyID string, updates map[string]interface{}) error {
	keyModel, err := models.Keys(
		models.KeyWhere.KeyID.EQ(keyID),
	).One(ctx, s.db)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return errors.New("key not found")
		}
		return errors.Wrap(err, "failed to get key metadata")
	}

	// 更新字段
	for field, value := range updates {
		switch field {
		case "description":
			if v, ok := value.(string); ok {
				keyModel.Description = null.StringFrom(v)
			}
		case "key_state":
			if v, ok := value.(string); ok {
				keyModel.KeyState = v
			}
		case "policy_id":
			if v, ok := value.(string); ok {
				keyModel.PolicyID = null.StringFrom(v)
			}
		case "tags":
			if v, ok := value.(map[string]string); ok {
				tagsJSON, err := json.Marshal(v)
				if err != nil {
					return errors.Wrap(err, "failed to marshal tags")
				}
				keyModel.Tags = null.JSONFrom(tagsJSON)
			}
		case "deletion_date":
			if v, ok := value.(*time.Time); ok {
				if v != nil {
					keyModel.DeletionDate = null.TimeFrom(*v)
				} else {
					keyModel.DeletionDate = null.Time{}
				}
			}
		}
	}

	keyModel.UpdatedAt = time.Now()

	_, err = keyModel.Update(ctx, s.db, boil.Infer())
	if err != nil {
		return errors.Wrap(err, "failed to update key metadata")
	}

	return nil
}

// DeleteKeyMetadata 删除密钥元数据
func (s *postgresqlStore) DeleteKeyMetadata(ctx context.Context, keyID string) error {
	keyModel, err := models.Keys(
		models.KeyWhere.KeyID.EQ(keyID),
	).One(ctx, s.db)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return errors.New("key not found")
		}
		return errors.Wrap(err, "failed to get key metadata")
	}

	_, err = keyModel.Delete(ctx, s.db)
	if err != nil {
		return errors.Wrap(err, "failed to delete key metadata")
	}

	return nil
}

// ListKeyMetadata 列出密钥元数据
func (s *postgresqlStore) ListKeyMetadata(ctx context.Context, filter *KeyFilter) ([]*KeyMetadata, error) {
	queryMods := []qm.QueryMod{}

	if filter != nil {
		if filter.State != "" {
			queryMods = append(queryMods, models.KeyWhere.KeyState.EQ(filter.State))
		}
		if filter.KeyType != "" {
			queryMods = append(queryMods, models.KeyWhere.KeyType.EQ(filter.KeyType))
		}
		if filter.Alias != "" {
			queryMods = append(queryMods, qm.Where("alias LIKE ?", filter.Alias+"%"))
		}
	}

	// 分页
	if filter != nil {
		if filter.Limit > 0 {
			queryMods = append(queryMods, qm.Limit(filter.Limit))
		}
		if filter.Offset > 0 {
			queryMods = append(queryMods, qm.Offset(filter.Offset))
		}
	}

	keyModels, err := models.Keys(queryMods...).All(ctx, s.db)
	if err != nil {
		return nil, errors.Wrap(err, "failed to list key metadata")
	}

	result := make([]*KeyMetadata, 0, len(keyModels))
	for _, keyModel := range keyModels {
		result = append(result, s.keyModelToMetadata(keyModel))
	}

	return result, nil
}

// SaveKeyVersion 保存密钥版本
func (s *postgresqlStore) SaveKeyVersion(ctx context.Context, version *KeyVersion) error {
	versionModel := &models.KeyVersion{
		KeyID:     version.KeyID,
		Version:   version.Version,
		HSMHandle: version.HSMHandle,
		IsPrimary: version.IsPrimary,
		CreatedAt: version.CreatedAt,
	}

	if err := versionModel.Insert(ctx, s.db, boil.Infer()); err != nil {
		return errors.Wrap(err, "failed to insert key version")
	}

	return nil
}

// GetKeyVersion 获取密钥版本
func (s *postgresqlStore) GetKeyVersion(ctx context.Context, keyID string, version int) (*KeyVersion, error) {
	versionModel, err := models.KeyVersions(
		models.KeyVersionWhere.KeyID.EQ(keyID),
		models.KeyVersionWhere.Version.EQ(version),
	).One(ctx, s.db)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, errors.New("key version not found")
		}
		return nil, errors.Wrap(err, "failed to get key version")
	}

	return &KeyVersion{
		KeyID:     versionModel.KeyID,
		Version:   versionModel.Version,
		HSMHandle: versionModel.HSMHandle,
		IsPrimary: versionModel.IsPrimary,
		CreatedAt: versionModel.CreatedAt,
	}, nil
}

// GetPrimaryKeyVersion 获取主版本密钥
func (s *postgresqlStore) GetPrimaryKeyVersion(ctx context.Context, keyID string) (*KeyVersion, error) {
	versionModel, err := models.KeyVersions(
		models.KeyVersionWhere.KeyID.EQ(keyID),
		models.KeyVersionWhere.IsPrimary.EQ(true),
	).One(ctx, s.db)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, errors.New("primary key version not found")
		}
		return nil, errors.Wrap(err, "failed to get primary key version")
	}

	return &KeyVersion{
		KeyID:     versionModel.KeyID,
		Version:   versionModel.Version,
		HSMHandle: versionModel.HSMHandle,
		IsPrimary: versionModel.IsPrimary,
		CreatedAt: versionModel.CreatedAt,
	}, nil
}

// ListKeyVersions 列出密钥的所有版本
func (s *postgresqlStore) ListKeyVersions(ctx context.Context, keyID string) ([]*KeyVersion, error) {
	versionModels, err := models.KeyVersions(
		models.KeyVersionWhere.KeyID.EQ(keyID),
		qm.OrderBy("version DESC"),
	).All(ctx, s.db)

	if err != nil {
		return nil, errors.Wrap(err, "failed to list key versions")
	}

	result := make([]*KeyVersion, 0, len(versionModels))
	for _, versionModel := range versionModels {
		result = append(result, &KeyVersion{
			KeyID:     versionModel.KeyID,
			Version:   versionModel.Version,
			HSMHandle: versionModel.HSMHandle,
			IsPrimary: versionModel.IsPrimary,
			CreatedAt: versionModel.CreatedAt,
		})
	}

	return result, nil
}

// UpdateKeyVersionPrimary 更新密钥版本的主版本标记
func (s *postgresqlStore) UpdateKeyVersionPrimary(ctx context.Context, keyID string, version int, isPrimary bool) error {
	versionModel, err := models.KeyVersions(
		models.KeyVersionWhere.KeyID.EQ(keyID),
		models.KeyVersionWhere.Version.EQ(version),
	).One(ctx, s.db)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return errors.New("key version not found")
		}
		return errors.Wrap(err, "failed to get key version")
	}

	versionModel.IsPrimary = isPrimary
	_, err = versionModel.Update(ctx, s.db, boil.Whitelist(models.KeyVersionColumns.IsPrimary))
	if err != nil {
		return errors.Wrap(err, "failed to update key version primary flag")
	}

	return nil
}

// SavePolicy 保存策略
func (s *postgresqlStore) SavePolicy(ctx context.Context, policy *Policy) error {
	policyJSON, err := json.Marshal(policy.PolicyDocument)
	if err != nil {
		return errors.Wrap(err, "failed to marshal policy document")
	}

	policyModel := &models.Policy{
		PolicyID:       policy.PolicyID,
		PolicyDocument: types.JSON(policyJSON),
		CreatedAt:      policy.CreatedAt,
		UpdatedAt:      policy.UpdatedAt,
	}

	if policy.Description != "" {
		policyModel.Description = null.StringFrom(policy.Description)
	}

	if err := policyModel.Insert(ctx, s.db, boil.Infer()); err != nil {
		return errors.Wrap(err, "failed to insert policy")
	}

	return nil
}

// GetPolicy 获取策略
func (s *postgresqlStore) GetPolicy(ctx context.Context, policyID string) (*Policy, error) {
	policyModel, err := models.Policies(
		models.PolicyWhere.PolicyID.EQ(policyID),
	).One(ctx, s.db)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, errors.New("policy not found")
		}
		return nil, errors.Wrap(err, "failed to get policy")
	}

	var policyDoc map[string]interface{}
	if err := json.Unmarshal(policyModel.PolicyDocument, &policyDoc); err != nil {
		return nil, errors.Wrap(err, "failed to unmarshal policy document")
	}

	return &Policy{
		PolicyID:       policyModel.PolicyID,
		Description:    policyModel.Description.String,
		PolicyDocument: policyDoc,
		CreatedAt:      policyModel.CreatedAt,
		UpdatedAt:      policyModel.UpdatedAt,
	}, nil
}

// ListPolicies 列出所有策略
func (s *postgresqlStore) ListPolicies(ctx context.Context) ([]*Policy, error) {
	policyModels, err := models.Policies().All(ctx, s.db)
	if err != nil {
		return nil, errors.Wrap(err, "failed to list policies")
	}

	result := make([]*Policy, 0, len(policyModels))
	for _, policyModel := range policyModels {
		var policyDoc map[string]interface{}
		if err := json.Unmarshal(policyModel.PolicyDocument, &policyDoc); err != nil {
			continue // 跳过无效的策略
		}

		result = append(result, &Policy{
			PolicyID:       policyModel.PolicyID,
			Description:    policyModel.Description.String,
			PolicyDocument: policyDoc,
			CreatedAt:      policyModel.CreatedAt,
			UpdatedAt:      policyModel.UpdatedAt,
		})
	}

	return result, nil
}

// UpdatePolicy 更新策略
func (s *postgresqlStore) UpdatePolicy(ctx context.Context, policyID string, policy *Policy) error {
	policyModel, err := models.Policies(
		models.PolicyWhere.PolicyID.EQ(policyID),
	).One(ctx, s.db)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return errors.New("policy not found")
		}
		return errors.Wrap(err, "failed to get policy")
	}

	policyJSON, err := json.Marshal(policy.PolicyDocument)
	if err != nil {
		return errors.Wrap(err, "failed to marshal policy document")
	}

	if policy.Description != "" {
		policyModel.Description = null.StringFrom(policy.Description)
	}
	policyModel.PolicyDocument = types.JSON(policyJSON)
	policyModel.UpdatedAt = time.Now()

	_, err = policyModel.Update(ctx, s.db, boil.Infer())
	if err != nil {
		return errors.Wrap(err, "failed to update policy")
	}

	return nil
}

// DeletePolicy 删除策略
func (s *postgresqlStore) DeletePolicy(ctx context.Context, policyID string) error {
	policyModel, err := models.Policies(
		models.PolicyWhere.PolicyID.EQ(policyID),
	).One(ctx, s.db)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return errors.New("policy not found")
		}
		return errors.Wrap(err, "failed to get policy")
	}

	_, err = policyModel.Delete(ctx, s.db)
	if err != nil {
		return errors.Wrap(err, "failed to delete policy")
	}

	return nil
}

// SaveAuditLog 保存审计日志
func (s *postgresqlStore) SaveAuditLog(ctx context.Context, event *AuditEvent) error {
	var detailsJSON null.JSON
	if event.Details != nil {
		detailsBytes, err := json.Marshal(event.Details)
		if err != nil {
			return errors.Wrap(err, "failed to marshal audit log details")
		}
		detailsJSON = null.JSONFrom(detailsBytes)
	}

	auditModel := &models.AuditLog{
		Timestamp: event.Timestamp,
		EventType: event.EventType,
		Operation: event.Operation,
		Result:    event.Result,
		Details:   detailsJSON,
	}

	if event.UserID != "" {
		auditModel.UserID = null.StringFrom(event.UserID)
	}
	if event.KeyID != "" {
		auditModel.KeyID = null.StringFrom(event.KeyID)
	}
	if event.IPAddress != "" {
		auditModel.IPAddress = null.StringFrom(event.IPAddress)
	}

	if err := auditModel.Insert(ctx, s.db, boil.Infer()); err != nil {
		return errors.Wrap(err, "failed to insert audit log")
	}

	return nil
}

// QueryAuditLogs 查询审计日志
func (s *postgresqlStore) QueryAuditLogs(ctx context.Context, filter *AuditLogFilter) ([]*AuditEvent, error) {
	queryMods := []qm.QueryMod{}

	//nolint:nestif // Filter building requires nested conditionals
	if filter != nil {
		if filter.StartTime != nil {
			queryMods = append(queryMods, qm.Where("timestamp >= ?", *filter.StartTime))
		}
		if filter.EndTime != nil {
			queryMods = append(queryMods, qm.Where("timestamp <= ?", *filter.EndTime))
		}
		if filter.KeyID != "" {
			queryMods = append(queryMods, models.AuditLogWhere.KeyID.EQ(null.StringFrom(filter.KeyID)))
		}
		if filter.UserID != "" {
			queryMods = append(queryMods, models.AuditLogWhere.UserID.EQ(null.StringFrom(filter.UserID)))
		}
		if filter.EventType != "" {
			queryMods = append(queryMods, models.AuditLogWhere.EventType.EQ(filter.EventType))
		}
		if filter.Operation != "" {
			queryMods = append(queryMods, models.AuditLogWhere.Operation.EQ(filter.Operation))
		}
		if filter.Result != "" {
			queryMods = append(queryMods, models.AuditLogWhere.Result.EQ(filter.Result))
		}
	}

	// 排序和分页
	queryMods = append(queryMods, qm.OrderBy("timestamp DESC"))
	if filter != nil {
		if filter.Limit > 0 {
			queryMods = append(queryMods, qm.Limit(filter.Limit))
		}
		if filter.Offset > 0 {
			queryMods = append(queryMods, qm.Offset(filter.Offset))
		}
	}

	auditModels, err := models.AuditLogs(queryMods...).All(ctx, s.db)
	if err != nil {
		return nil, errors.Wrap(err, "failed to query audit logs")
	}

	result := make([]*AuditEvent, 0, len(auditModels))
	for _, auditModel := range auditModels {
		var details map[string]interface{}
		if auditModel.Details.Valid {
			if err := json.Unmarshal(auditModel.Details.JSON, &details); err != nil {
				details = nil
			}
		}

		result = append(result, &AuditEvent{
			Timestamp: auditModel.Timestamp,
			EventType: auditModel.EventType,
			UserID:    auditModel.UserID.String,
			KeyID:     auditModel.KeyID.String,
			Operation: auditModel.Operation,
			Result:    auditModel.Result,
			Details:   details,
			IPAddress: auditModel.IPAddress.String,
		})
	}

	return result, nil
}

// keyModelToMetadata 将 SQLBoiler 模型转换为 KeyMetadata
//
//nolint:funcorder // keyModelToMetadata is a helper method, should be at the end
func (s *postgresqlStore) keyModelToMetadata(keyModel *models.Key) *KeyMetadata {
	var keySpec map[string]interface{}
	if keyModel.KeySpec.Valid {
		_ = json.Unmarshal(keyModel.KeySpec.JSON, &keySpec)
	}

	var tags map[string]string
	if keyModel.Tags.Valid {
		_ = json.Unmarshal(keyModel.Tags.JSON, &tags)
	}

	var deletionDate *time.Time
	if keyModel.DeletionDate.Valid {
		deletionDate = &keyModel.DeletionDate.Time
	}

	return &KeyMetadata{
		KeyID:        keyModel.KeyID,
		Alias:        keyModel.Alias.String,
		Description:  keyModel.Description.String,
		KeyType:      keyModel.KeyType,
		KeyState:     keyModel.KeyState,
		KeySpec:      keySpec,
		HSMHandle:    keyModel.HSMHandle,
		PolicyID:     keyModel.PolicyID.String,
		CreatedAt:    keyModel.CreatedAt,
		UpdatedAt:    keyModel.UpdatedAt,
		DeletionDate: deletionDate,
		Tags:         tags,
	}
}

// SaveSecret 保存 Secret
func (s *postgresqlStore) SaveSecret(ctx context.Context, secret *Secret) error {
	query := `
		INSERT INTO secrets (key_id, encrypted_data, kms_key_id, key_version, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6)
	`
	_, err := s.db.ExecContext(ctx, query,
		secret.KeyID,
		secret.EncryptedData,
		secret.KMSKeyID,
		secret.KeyVersion,
		secret.CreatedAt,
		secret.UpdatedAt,
	)
	if err != nil {
		return errors.Wrap(err, "failed to insert secret")
	}

	return nil
}

// GetSecret 获取 Secret
func (s *postgresqlStore) GetSecret(ctx context.Context, keyID string) (*Secret, error) {
	query := `
		SELECT key_id, encrypted_data, kms_key_id, key_version, created_at, updated_at
		FROM secrets
		WHERE key_id = $1
	`
	var secret Secret
	err := s.db.QueryRowContext(ctx, query, keyID).Scan(
		&secret.KeyID,
		&secret.EncryptedData,
		&secret.KMSKeyID,
		&secret.KeyVersion,
		&secret.CreatedAt,
		&secret.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, errors.New("secret not found")
		}
		return nil, errors.Wrap(err, "failed to get secret")
	}

	return &secret, nil
}

// UpdateSecret 更新 Secret
func (s *postgresqlStore) UpdateSecret(ctx context.Context, keyID string, secret *Secret) error {
	query := `
		UPDATE secrets
		SET encrypted_data = $1, kms_key_id = $2, key_version = $3, updated_at = $4
		WHERE key_id = $5
	`
	result, err := s.db.ExecContext(ctx, query,
		secret.EncryptedData,
		secret.KMSKeyID,
		secret.KeyVersion,
		secret.UpdatedAt,
		keyID,
	)
	if err != nil {
		return errors.Wrap(err, "failed to update secret")
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return errors.Wrap(err, "failed to get rows affected")
	}
	if rowsAffected == 0 {
		return errors.New("secret not found")
	}

	return nil
}

// DeleteSecret 删除 Secret
func (s *postgresqlStore) DeleteSecret(ctx context.Context, keyID string) error {
	query := `DELETE FROM secrets WHERE key_id = $1`
	result, err := s.db.ExecContext(ctx, query, keyID)
	if err != nil {
		return errors.Wrap(err, "failed to delete secret")
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return errors.Wrap(err, "failed to get rows affected")
	}
	if rowsAffected == 0 {
		return errors.New("secret not found")
	}

	return nil
}

// SecretExists 检查 Secret 是否存在
func (s *postgresqlStore) SecretExists(ctx context.Context, keyID string) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM secrets WHERE key_id = $1)`
	var exists bool
	err := s.db.QueryRowContext(ctx, query, keyID).Scan(&exists)
	if err != nil {
		return false, errors.Wrap(err, "failed to check secret existence")
	}

	return exists, nil
}
