package storage

import (
	"context"
	"time"
)

// MetadataStore 定义元数据存储接口
// 所有存储后端实现（PostgreSQL、Consul、文件系统等）都必须实现此接口
//
//nolint:interfacebloat // MetadataStore intentionally has many methods for comprehensive storage operations
type MetadataStore interface {
	// 密钥元数据操作
	SaveKeyMetadata(ctx context.Context, key *KeyMetadata) error
	GetKeyMetadata(ctx context.Context, keyID string) (*KeyMetadata, error)
	UpdateKeyMetadata(ctx context.Context, keyID string, updates map[string]interface{}) error
	DeleteKeyMetadata(ctx context.Context, keyID string) error
	ListKeyMetadata(ctx context.Context, filter *KeyFilter) ([]*KeyMetadata, error)

	// 密钥版本操作
	SaveKeyVersion(ctx context.Context, version *KeyVersion) error
	GetKeyVersion(ctx context.Context, keyID string, version int) (*KeyVersion, error)
	GetPrimaryKeyVersion(ctx context.Context, keyID string) (*KeyVersion, error)
	ListKeyVersions(ctx context.Context, keyID string) ([]*KeyVersion, error)
	UpdateKeyVersionPrimary(ctx context.Context, keyID string, version int, isPrimary bool) error

	// 策略操作
	SavePolicy(ctx context.Context, policy *Policy) error
	GetPolicy(ctx context.Context, policyID string) (*Policy, error)
	ListPolicies(ctx context.Context) ([]*Policy, error)
	UpdatePolicy(ctx context.Context, policyID string, policy *Policy) error
	DeletePolicy(ctx context.Context, policyID string) error

	// 审计日志操作
	SaveAuditLog(ctx context.Context, event *AuditEvent) error
	QueryAuditLogs(ctx context.Context, filter *AuditLogFilter) ([]*AuditEvent, error)

	// Secret 操作
	SaveSecret(ctx context.Context, secret *Secret) error
	GetSecret(ctx context.Context, keyID string) (*Secret, error)
	UpdateSecret(ctx context.Context, keyID string, secret *Secret) error
	DeleteSecret(ctx context.Context, keyID string) error
	SecretExists(ctx context.Context, keyID string) (bool, error)
}

// KeyFilter 密钥查询过滤器
type KeyFilter struct {
	State   string            // 密钥状态过滤
	KeyType string            // 密钥类型过滤
	Alias   string            // 别名过滤（前缀匹配）
	Tags    map[string]string // 标签过滤
	Limit   int               // 返回数量限制
	Offset  int               // 偏移量
}

// AuditLogFilter 审计日志查询过滤器
type AuditLogFilter struct {
	StartTime *time.Time
	EndTime   *time.Time
	KeyID     string
	UserID    string
	EventType string
	Operation string
	Result    string
	Limit     int
	Offset    int
}
