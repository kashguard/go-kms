package hsm

import (
	"context"
)

// Adapter 定义 HSM 适配器接口
// 所有 HSM 实现（SoftHSM、硬件 HSM、CloudHSM）都必须实现此接口
type Adapter interface {
	// GenerateKey 在 HSM 内生成密钥，返回密钥句柄
	// 密钥永不离开 HSM，只返回句柄用于后续操作
	GenerateKey(ctx context.Context, keySpec *KeySpec) (string, error)

	// ImportKey 导入外部密钥到 HSM，返回密钥句柄
	// keyMaterial 是加密的密钥材料
	ImportKey(ctx context.Context, keyMaterial []byte, keySpec *KeySpec) (string, error)

	// DeleteKey 在 HSM 内删除密钥
	DeleteKey(ctx context.Context, handle string) error

	// Encrypt 使用指定密钥句柄加密数据
	// 加密操作在 HSM 内执行，密钥不离开 HSM
	Encrypt(ctx context.Context, handle string, plaintext []byte) ([]byte, error)

	// Decrypt 使用指定密钥句柄解密数据
	// 解密操作在 HSM 内执行，密钥不离开 HSM
	Decrypt(ctx context.Context, handle string, ciphertext []byte) ([]byte, error)

	// Sign 使用指定密钥句柄对消息摘要进行签名
	// digest: 消息摘要（已哈希）
	// algorithm: 签名算法（ECDSA_SHA256, ECDSA_SHA384, ECDSA_SHA512, ED25519）
	Sign(ctx context.Context, handle string, digest []byte, algorithm string) ([]byte, error)

	// Verify 使用指定密钥句柄验证签名
	// digest: 消息摘要（已哈希）
	// signature: 签名数据
	// algorithm: 签名算法
	Verify(ctx context.Context, handle string, digest []byte, signature []byte, algorithm string) (bool, error)

	// GetKeyAttributes 获取密钥属性
	GetKeyAttributes(ctx context.Context, handle string) (*KeyAttributes, error)
}
