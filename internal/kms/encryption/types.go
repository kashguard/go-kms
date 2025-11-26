package encryption

// EncryptRequest 加密请求
type EncryptRequest struct {
	KeyID             string
	Plaintext         []byte
	EncryptionContext map[string]string
}

// EncryptResponse 加密响应
type EncryptResponse struct {
	CiphertextBlob []byte
	KeyID          string
	KeyVersion     int
}

// DecryptRequest 解密请求
type DecryptRequest struct {
	CiphertextBlob    []byte
	EncryptionContext map[string]string
}

// DecryptResponse 解密响应
type DecryptResponse struct {
	Plaintext  []byte
	KeyID      string
	KeyVersion int
}

// GenerateDataKeyRequest 生成数据密钥请求
type GenerateDataKeyRequest struct {
	KeyID             string
	KeySpec           string // AES_256
	NumberOfBytes     int
	EncryptionContext map[string]string
	ReturnPlaintext   bool
}

// GenerateDataKeyResponse 生成数据密钥响应
type GenerateDataKeyResponse struct {
	Plaintext      []byte // 可选，如果 ReturnPlaintext=false 则为空
	CiphertextBlob []byte
	KeyID          string
}
