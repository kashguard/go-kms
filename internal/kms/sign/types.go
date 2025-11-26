package sign

// SignRequest 签名请求
//
//nolint:revive // SignRequest is the standard naming for sign requests
type SignRequest struct {
	KeyID     string
	Message   []byte
	Algorithm string // ECDSA_SHA256, ECDSA_SHA384, ECDSA_SHA512, ED25519
	Mode      string // RAW（原始数据）或 DIGEST（消息摘要）
}

// SignResponse 签名响应
//
//nolint:revive // SignResponse is the standard naming for sign responses
type SignResponse struct {
	Signature  []byte
	KeyID      string
	KeyVersion int
	Algorithm  string
}

// VerifyRequest 验证请求
type VerifyRequest struct {
	KeyID     string
	Message   []byte
	Signature []byte
	Algorithm string // ECDSA_SHA256, ECDSA_SHA384, ECDSA_SHA512, ED25519
	Mode      string // RAW（原始数据）或 DIGEST（消息摘要）
}

// VerifyResponse 验证响应
type VerifyResponse struct {
	Valid      bool
	KeyID      string
	KeyVersion int
}
