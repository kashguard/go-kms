package hsm

// KeySpec 定义密钥规格
type KeySpec struct {
	KeyType    string            // 密钥类型：ECC_SECP256K1, ECC_P256, ED25519, AES_256
	KeySize    int               // 密钥大小（位）
	Algorithm  string            // 算法名称
	Attributes map[string]string // 其他属性
}

// KeyAttributes 密钥属性
type KeyAttributes struct {
	KeyType    string
	KeySize    int
	Algorithm  string
	CanEncrypt bool
	CanDecrypt bool
	CanSign    bool
	CanVerify  bool
}
