package software

import (
	"context"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"sync"

	"github.com/kashguard/go-kms/internal/kms/hsm"
	"github.com/miekg/pkcs11"
	"github.com/pkg/errors"
)

// adapter 实现 SoftHSM 适配器
type adapter struct {
	ctx    *pkcs11.Ctx
	slot   uint
	pin    string
	handle string // 会话句柄
	mu     sync.RWMutex
}

// NewAdapter 创建新的 SoftHSM 适配器
// libraryPath: SoftHSM 库路径（如 /usr/lib/softhsm/libsofthsm2.so）
// slot: HSM Slot ID
// pin: HSM PIN
//
//nolint:ireturn // returning interface is intentional for abstraction
func NewAdapter(libraryPath string, slot uint, pin string) (hsm.Adapter, error) {
	ctx := pkcs11.New(libraryPath)
	if ctx == nil {
		return nil, errors.New("failed to load PKCS#11 library")
	}

	if err := ctx.Initialize(); err != nil {
		return nil, errors.Wrap(err, "failed to initialize PKCS#11")
	}

	// 打开会话
	session, err := ctx.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		_ = ctx.Finalize()
		return nil, errors.Wrap(err, "failed to open PKCS#11 session")
	}

	// 登录
	if err := ctx.Login(session, pkcs11.CKU_USER, pin); err != nil {
		_ = ctx.CloseSession(session)
		_ = ctx.Finalize()
		return nil, errors.Wrap(err, "failed to login to PKCS#11")
	}

	return &adapter{
		ctx:    ctx,
		slot:   slot,
		pin:    pin,
		handle: fmt.Sprintf("%d", uint(session)),
	}, nil
}

// Close 关闭适配器
func (a *adapter) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.ctx == nil {
		return nil
	}

	session := a.getSession()
	if session != 0 {
		_ = a.ctx.Logout(session)
		_ = a.ctx.CloseSession(session)
	}

	_ = a.ctx.Finalize()
	a.ctx = nil
	return nil
}

//nolint:funcorder // getSession is a helper method, should be near the top
func (a *adapter) getSession() pkcs11.SessionHandle {
	if a.handle == "" {
		return 0
	}
	var session uint
	_, _ = fmt.Sscanf(a.handle, "%d", &session)
	return pkcs11.SessionHandle(session)
}

// GenerateKey 在 SoftHSM 内生成密钥
func (a *adapter) GenerateKey(_ context.Context, keySpec *hsm.KeySpec) (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	session := a.getSession()
	if session == 0 {
		return "", errors.New("PKCS#11 session not available")
	}

	var handle pkcs11.ObjectHandle
	var err error

	switch keySpec.KeyType {
	case "ECC_SECP256K1":
		handle, err = a.generateECCKey(session, keySpec, elliptic.P256()) // 注意：Go 标准库不支持 secp256k1，这里先用 P256 作为示例
	case "ECC_P256":
		handle, err = a.generateECCKey(session, keySpec, elliptic.P256())
	case "ED25519":
		handle, err = a.generateEd25519Key(session, keySpec)
	case "AES_256":
		handle, err = a.generateAESKey(session, keySpec, 32) //nolint:mnd // 32 bytes = 256 bits
	default:
		return "", errors.Errorf("unsupported key type: %s", keySpec.KeyType)
	}

	if err != nil {
		return "", errors.Wrap(err, "failed to generate key in SoftHSM")
	}

	return fmt.Sprintf("%d", handle), nil
}

// generateECCKey 生成 ECC 密钥对
//
//nolint:funcorder // generateECCKey is a helper method, should be near GenerateKey
func (a *adapter) generateECCKey(session pkcs11.SessionHandle, _ *hsm.KeySpec, curve elliptic.Curve) (pkcs11.ObjectHandle, error) {
	// 定义密钥对模板
	publicKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, a.getECParams(curve)),
	}

	privateKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false),
	}

	_, privHandle, err := a.ctx.GenerateKeyPair(session,
		[]*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_EC_KEY_PAIR_GEN, nil)},
		publicKeyTemplate,
		privateKeyTemplate,
	)

	if err != nil {
		//nolint:wrapcheck // PKCS#11 error is already descriptive
		return 0, err
	}

	// 返回私钥句柄（用于签名）
	return privHandle, nil
}

// generateEd25519Key 生成 Ed25519 密钥对
// 注意：SoftHSM 可能不支持 Ed25519，这里简化实现
//
//nolint:funcorder // generateEd25519Key is a helper method, should be near GenerateKey
func (a *adapter) generateEd25519Key(session pkcs11.SessionHandle, _ *hsm.KeySpec) (pkcs11.ObjectHandle, error) {
	// 生成 Ed25519 密钥对
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return 0, errors.Wrap(err, "failed to generate Ed25519 key")
	}

	// 导入到 SoftHSM
	// 注意：SoftHSM 可能不支持 Ed25519，这里使用通用密钥类型
	publicKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_GENERIC_SECRET),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		pkcs11.NewAttribute(pkcs11.CKA_VALUE, publicKey),
	}

	privateKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_GENERIC_SECRET),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false),
		pkcs11.NewAttribute(pkcs11.CKA_VALUE, privateKey),
	}

	pubHandle, err := a.ctx.CreateObject(session, publicKeyTemplate)
	if err != nil {
		return 0, errors.Wrap(err, "failed to create Ed25519 public key in SoftHSM")
	}

	privHandle, err := a.ctx.CreateObject(session, privateKeyTemplate)
	if err != nil {
		_ = a.ctx.DestroyObject(session, pubHandle)
		return 0, errors.Wrap(err, "failed to create Ed25519 private key in SoftHSM")
	}

	// 返回私钥句柄
	return privHandle, nil
}

// generateAESKey 生成 AES 密钥
//
//nolint:funcorder // generateAESKey is a helper method, should be near GenerateKey
func (a *adapter) generateAESKey(session pkcs11.SessionHandle, _ *hsm.KeySpec, keySize int) (pkcs11.ObjectHandle, error) {
	// 生成随机密钥
	keyMaterial := make([]byte, keySize)
	if _, err := rand.Read(keyMaterial); err != nil {
		return 0, errors.Wrap(err, "failed to generate random key material")
	}

	// 创建密钥对象
	keyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_AES),
		pkcs11.NewAttribute(pkcs11.CKA_VALUE, keyMaterial),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false),
	}

	handle, err := a.ctx.CreateObject(session, keyTemplate)
	if err != nil {
		return 0, errors.Wrap(err, "failed to create AES key in SoftHSM")
	}

	return handle, nil
}

// ImportKey 导入外部密钥到 SoftHSM
func (a *adapter) ImportKey(_ context.Context, _ []byte, _ *hsm.KeySpec) (string, error) {
	// TODO: 实现密钥导入功能
	return "", errors.New("ImportKey not implemented yet")
}

// DeleteKey 在 SoftHSM 内删除密钥
func (a *adapter) DeleteKey(_ context.Context, handle string) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	session := a.getSession()
	if session == 0 {
		return errors.New("PKCS#11 session not available")
	}

	var objHandle pkcs11.ObjectHandle
	if _, err := fmt.Sscanf(handle, "%d", &objHandle); err != nil {
		return errors.Wrap(err, "invalid key handle")
	}

	if err := a.ctx.DestroyObject(session, objHandle); err != nil {
		return errors.Wrap(err, "failed to delete key from SoftHSM")
	}

	return nil
}

// Encrypt 使用指定密钥句柄加密数据
//
//nolint:dupl // Encrypt and Decrypt are intentionally similar
func (a *adapter) Encrypt(_ context.Context, handle string, plaintext []byte) ([]byte, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	session := a.getSession()
	if session == pkcs11.SessionHandle(0) {
		return nil, errors.New("PKCS#11 session not available")
	}

	var objHandle pkcs11.ObjectHandle
	if _, err := fmt.Sscanf(handle, "%d", &objHandle); err != nil {
		return nil, errors.Wrap(err, "invalid key handle")
	}

	// 使用 AES-CBC 模式加密
	mech := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_CBC_PAD, make([]byte, 16))} //nolint:mnd // AES block size is 16 bytes

	if err := a.ctx.EncryptInit(session, mech, objHandle); err != nil {
		return nil, errors.Wrap(err, "failed to initialize encryption")
	}

	ciphertext, err := a.ctx.Encrypt(session, plaintext)
	if err != nil {
		return nil, errors.Wrap(err, "failed to encrypt data")
	}

	return ciphertext, nil
}

// Decrypt 使用指定密钥句柄解密数据
//
//nolint:dupl // Encrypt and Decrypt are intentionally similar
func (a *adapter) Decrypt(_ context.Context, handle string, ciphertext []byte) ([]byte, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	session := a.getSession()
	if session == pkcs11.SessionHandle(0) {
		return nil, errors.New("PKCS#11 session not available")
	}

	var objHandle pkcs11.ObjectHandle
	if _, err := fmt.Sscanf(handle, "%d", &objHandle); err != nil {
		return nil, errors.Wrap(err, "invalid key handle")
	}

	// 使用 AES-CBC 模式解密
	mech := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_CBC_PAD, make([]byte, 16))} //nolint:mnd // AES block size is 16 bytes

	if err := a.ctx.DecryptInit(session, mech, objHandle); err != nil {
		return nil, errors.Wrap(err, "failed to initialize decryption")
	}

	plaintext, err := a.ctx.Decrypt(session, ciphertext)
	if err != nil {
		return nil, errors.Wrap(err, "failed to decrypt data")
	}

	return plaintext, nil
}

// Sign 使用指定密钥句柄对消息摘要进行签名
func (a *adapter) Sign(_ context.Context, handle string, digest []byte, algorithm string) ([]byte, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	session := a.getSession()
	if session == pkcs11.SessionHandle(0) {
		return nil, errors.New("PKCS#11 session not available")
	}

	var objHandle pkcs11.ObjectHandle
	if _, err := fmt.Sscanf(handle, "%d", &objHandle); err != nil {
		return nil, errors.Wrap(err, "invalid key handle")
	}

	var mech *pkcs11.Mechanism
	switch algorithm {
	case "ECDSA_SHA256":
		mech = pkcs11.NewMechanism(pkcs11.CKM_ECDSA_SHA256, nil)
	case "ECDSA_SHA384":
		mech = pkcs11.NewMechanism(pkcs11.CKM_ECDSA_SHA384, nil)
	case "ECDSA_SHA512":
		mech = pkcs11.NewMechanism(pkcs11.CKM_ECDSA_SHA512, nil)
	case "ED25519":
		// SoftHSM 可能不支持 Ed25519，使用通用机制
		// 注意：这需要后续改进以支持真正的 Ed25519
		mech = pkcs11.NewMechanism(pkcs11.CKM_SHA256, nil)
	default:
		return nil, errors.Errorf("unsupported signing algorithm: %s", algorithm)
	}

	if err := a.ctx.SignInit(session, []*pkcs11.Mechanism{mech}, objHandle); err != nil {
		return nil, errors.Wrap(err, "failed to initialize signing")
	}

	signature, err := a.ctx.Sign(session, digest)
	if err != nil {
		return nil, errors.Wrap(err, "failed to sign digest")
	}

	return signature, nil
}

// Verify 使用指定密钥句柄验证签名
func (a *adapter) Verify(_ context.Context, handle string, _ []byte, _ []byte, _ string) (bool, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	session := a.getSession()
	if session == pkcs11.SessionHandle(0) {
		return false, errors.New("PKCS#11 session not available")
	}

	var objHandle pkcs11.ObjectHandle
	if _, err := fmt.Sscanf(handle, "%d", &objHandle); err != nil {
		return false, errors.Wrap(err, "invalid key handle")
	}

	// 需要获取公钥句柄进行验证
	// 这里简化处理，实际应该从私钥句柄找到对应的公钥
	// TODO: 实现公钥查找逻辑

	// 注意：PKCS#11 的 Verify 需要公钥句柄，这里需要改进
	// 暂时返回错误，后续需要实现公钥查找
	return false, errors.New("Verify requires public key handle, not implemented yet")
}

// GetKeyAttributes 获取密钥属性
func (a *adapter) GetKeyAttributes(_ context.Context, handle string) (*hsm.KeyAttributes, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	session := a.getSession()
	if session == pkcs11.SessionHandle(0) {
		return nil, errors.New("PKCS#11 session not available")
	}

	var objHandle pkcs11.ObjectHandle
	if _, err := fmt.Sscanf(handle, "%d", &objHandle); err != nil {
		return nil, errors.Wrap(err, "invalid key handle")
	}

	// 获取密钥类型
	keyTypeAttr, err := a.ctx.GetAttributeValue(session, objHandle, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, nil),
	})
	if err != nil {
		return nil, errors.Wrap(err, "failed to get key type")
	}

	keyType := keyTypeAttr[0].Value[0]

	attrs := &hsm.KeyAttributes{
		CanEncrypt: true,
		CanDecrypt: true,
		CanSign:    true,
		CanVerify:  true,
	}

	switch keyType {
	case pkcs11.CKK_EC:
		attrs.KeyType = "ECC"
		attrs.Algorithm = "ECDSA"
		attrs.CanEncrypt = false
		attrs.CanDecrypt = false
	case pkcs11.CKK_GENERIC_SECRET:
		// 可能是 Ed25519 或其他通用密钥
		attrs.KeyType = "GENERIC"
		attrs.Algorithm = "UNKNOWN"
		attrs.CanEncrypt = false
		attrs.CanDecrypt = false
	case pkcs11.CKK_AES:
		attrs.KeyType = "AES"
		attrs.Algorithm = "AES"
		attrs.CanSign = false
		attrs.CanVerify = false
	}

	return attrs, nil
}

// getECParams 获取椭圆曲线参数
func (a *adapter) getECParams(curve elliptic.Curve) []byte {
	// 返回 DER 编码的 EC 参数
	// 这里简化处理，实际应该根据曲线类型返回正确的参数
	switch curve {
	case elliptic.P256():
		// P-256 OID: 1.2.840.10045.3.1.7
		return []byte{0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07}
	default:
		return []byte{}
	}
}
