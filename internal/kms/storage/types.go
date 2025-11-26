package storage

import (
	"time"
)

// KeyMetadata 密钥元数据
type KeyMetadata struct {
	KeyID        string
	Alias        string
	Description  string
	KeyType      string
	KeyState     string
	KeySpec      map[string]interface{}
	HSMHandle    string
	PolicyID     string
	CreatedAt    time.Time
	UpdatedAt    time.Time
	DeletionDate *time.Time
	Tags         map[string]string
}

// KeyVersion 密钥版本
type KeyVersion struct {
	KeyID     string
	Version   int
	HSMHandle string
	IsPrimary bool
	CreatedAt time.Time
}

// Policy 策略定义
type Policy struct {
	PolicyID       string
	Description    string
	PolicyDocument map[string]interface{}
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// AuditEvent 审计事件
type AuditEvent struct {
	Timestamp time.Time
	EventType string
	UserID    string
	KeyID     string
	Operation string
	Result    string
	Details   map[string]interface{}
	IPAddress string
}

// Secret 存储数据
type Secret struct {
	KeyID         string
	EncryptedData []byte
	KMSKeyID      string
	KeyVersion    int
	CreatedAt     time.Time
	UpdatedAt     time.Time
}
