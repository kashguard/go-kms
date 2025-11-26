package key

import (
	"time"
)

// KeyState 密钥状态
//
//nolint:revive // KeyState is the standard naming for key states
type KeyState string

const (
	KeyStateEnabled         KeyState = "Enabled"
	KeyStateDisabled        KeyState = "Disabled"
	KeyStatePendingDeletion KeyState = "PendingDeletion"
	KeyStateDeleted         KeyState = "Deleted"
)

// KeyType 密钥类型
//
//nolint:revive // KeyType is the standard naming for key types
type KeyType string

const (
	KeyTypeECCSecp256k1 KeyType = "ECC_SECP256K1"
	KeyTypeECCP256      KeyType = "ECC_P256"
	KeyTypeEd25519      KeyType = "ED25519"
	KeyTypeAES256       KeyType = "AES_256"
)

// KeyMetadata 密钥元数据
//
//nolint:revive // KeyMetadata is the standard naming for key metadata
type KeyMetadata struct {
	KeyID         string
	Alias         string
	Description   string
	KeyType       KeyType
	KeyState      KeyState
	KeySpec       *KeySpec
	HSMHandle     string
	PolicyID      string
	CreatedAt     time.Time
	UpdatedAt     time.Time
	DeletionDate  *time.Time
	Tags          map[string]string
	LatestVersion int
}

// KeySpec 密钥规格
//
//nolint:revive // KeySpec is the standard naming for key specifications
type KeySpec struct {
	Algorithm  string            `json:"algorithm"`
	KeySize    int               `json:"key_size"`
	Curve      string            `json:"curve,omitempty"`
	Attributes map[string]string `json:"attributes,omitempty"`
}

// CreateKeyRequest 创建密钥请求
type CreateKeyRequest struct {
	Alias       string
	Description string
	KeyType     KeyType
	KeySpec     *KeySpec
	PolicyID    string
	Tags        map[string]string
}

// UpdateKeyRequest 更新密钥请求
type UpdateKeyRequest struct {
	Description  string
	PolicyID     string
	Tags         map[string]string
	DeletionDate *time.Time
}

// KeyFilter 密钥查询过滤器
//
//nolint:revive // KeyFilter is the standard naming for key filters
type KeyFilter struct {
	State   string
	KeyType string
	Alias   string
	Tags    map[string]string
	Limit   int
	Offset  int
}

// KeyVersion 密钥版本
//
//nolint:revive // KeyVersion is the standard naming for key versions
type KeyVersion struct {
	KeyID     string
	Version   int
	HSMHandle string
	IsPrimary bool
	CreatedAt time.Time
}
