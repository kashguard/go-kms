package software

import (
	"context"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/kashguard/go-kms/internal/kms/hsm"
	"github.com/miekg/pkcs11"
	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"
)

const (
	// PKCS#11 constants are not exposed by github.com/miekg/pkcs11 yet.
	mechanismECEdwardsKeyPair = uint(0x1055) // CKM_EC_EDWARDS_KEY_PAIR_GEN
	mechanismEDDSA            = uint(0x1057) // CKM_EDDSA
	keyTypeECEdwards          = uint(0x40)   // CKK_EC_EDWARDS
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
	if libraryPath == "" {
		return nil, errors.New("HSM library path is required, set KMS_HSM_LIBRARY environment variable")
	}

	// 检查库文件是否存在
	if _, err := os.Stat(libraryPath); os.IsNotExist(err) {
		return nil, errors.Errorf(
			"HSM library file not found at path: %s. "+
				"Please install SoftHSM2 and set KMS_HSM_LIBRARY to the correct library path. "+
				"On Ubuntu/Debian: apt-get install softhsm2. "+
				"On macOS: brew install softhsm. "+
				"Common paths: /usr/lib/softhsm/libsofthsm2.so (Linux) or /usr/local/lib/softhsm/libsofthsm2.so (macOS)",
			libraryPath,
		)
	}

	ctx := pkcs11.New(libraryPath)
	if ctx == nil {
		return nil, errors.Errorf(
			"failed to load PKCS#11 library from path: %s. "+
				"This may indicate that the library file is corrupted or incompatible with your system architecture. "+
				"Please verify the library path and ensure SoftHSM2 is properly installed",
			libraryPath,
		)
	}

	if err := ctx.Initialize(); err != nil {
		_ = ctx.Finalize()
		return nil, errors.Wrapf(
			err,
			"failed to initialize PKCS#11. "+
				"This usually means SoftHSM is not properly configured. "+
				"Please ensure SoftHSM is installed and initialized. "+
				"Run: softhsm2-util --init-token --slot %d --label 'KMS' --pin %s --so-pin %s",
			slot, pin, pin,
		)
	}

	// 检查 slot 是否存在
	slots, err := ctx.GetSlotList(true)
	if err != nil {
		_ = ctx.Finalize()
		return nil, errors.Wrap(err, "failed to get PKCS#11 slot list")
	}

	slotExists := false
	for _, s := range slots {
		if s == slot {
			slotExists = true
			break
		}
	}

	if !slotExists {
		_ = ctx.Finalize()
		return nil, errors.Errorf(
			"PKCS#11 slot %d does not exist. Available slots: %v. "+
				"Please initialize a token in the specified slot. "+
				"Run: softhsm2-util --init-token --slot %d --label 'KMS' --pin %s --so-pin %s",
			slot, slots, slot, pin, pin,
		)
	}

	// 打开会话
	session, err := ctx.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		_ = ctx.Finalize()
		return nil, errors.Wrapf(
			err,
			"failed to open PKCS#11 session on slot %d. "+
				"This may indicate the token is not initialized or the slot is locked. "+
				"Try: softhsm2-util --init-token --slot %d --label 'KMS' --pin %s --so-pin %s",
			slot, slot, pin, pin,
		)
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

	var err error

	switch keySpec.KeyType {
	case "ECC_SECP256K1":
		label := getAttributeValue(keySpec.Attributes, "label", generateLabel())
		class := getAttributeValue(keySpec.Attributes, "class", "private")
		_, err = a.generateECCKey(session, keySpec, elliptic.P256(), label)
		if err != nil {
			return "", errors.Wrap(err, "failed to generate key in SoftHSM")
		}
		return buildLabelHandle(class, label), nil
	case "ECC_P256":
		label := getAttributeValue(keySpec.Attributes, "label", generateLabel())
		class := getAttributeValue(keySpec.Attributes, "class", "private")
		_, err = a.generateECCKey(session, keySpec, elliptic.P256(), label)
		if err != nil {
			return "", errors.Wrap(err, "failed to generate key in SoftHSM")
		}
		return buildLabelHandle(class, label), nil
	case "ED25519":
		// Ed25519 在软件中生成，返回特殊格式的句柄
		handleID, err := a.generateEd25519Key(session, keySpec)
		if err != nil {
			return "", errors.Wrap(err, "failed to generate Ed25519 key")
		}
		return handleID, nil
	case "AES_256":
		label := getAttributeValue(keySpec.Attributes, "label", generateLabel())
		class := getAttributeValue(keySpec.Attributes, "class", "secret")
		_, err = a.generateAESKey(session, keySpec, 32, label) //nolint:mnd // 32 bytes = 256 bits
		if err != nil {
			return "", errors.Wrap(err, "failed to generate key in SoftHSM")
		}
		return buildLabelHandle(class, label), nil
	default:
		return "", errors.Errorf("unsupported key type: %s", keySpec.KeyType)
	}
}

// generateECCKey 生成 ECC 密钥对
//
//nolint:funcorder // generateECCKey is a helper method, should be near GenerateKey
func (a *adapter) generateECCKey(session pkcs11.SessionHandle, keySpec *hsm.KeySpec, curve elliptic.Curve, label string) (pkcs11.ObjectHandle, error) {
	// 定义密钥对模板
	labelBytes := []byte(label)
	publicKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, a.getECParams(curve)),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, labelBytes),
		pkcs11.NewAttribute(pkcs11.CKA_ID, labelBytes),
	}

	privateKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, labelBytes),
		pkcs11.NewAttribute(pkcs11.CKA_ID, labelBytes),
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
// 首先尝试在 HSM 中生成，如果 HSM 不支持则回退到软件生成并加密存储
// SoftHSM2 支持 Ed25519（需要与支持 Ed25519 的 OpenSSL 编译）
//
//nolint:funcorder // generateEd25519Key is a helper method, should be near GenerateKey
func (a *adapter) generateEd25519Key(session pkcs11.SessionHandle, _ *hsm.KeySpec) (string, error) {
	// Ed25519 OID: 1.3.101.112 (DER 编码: 06 03 2b 65 70)
	ed25519OID := []byte{0x06, 0x03, 0x2b, 0x65, 0x70}

	// 尝试方法1：使用 CKM_EC_EDWARDS_KEY_PAIR_GEN + CKK_EC_EDWARDS
	// CKA_EC_PARAMS is required to specify which Edwards curve (Ed25519 vs Ed448)
	labelBytes1 := []byte(generateLabel())
	publicKeyTemplate1 := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, keyTypeECEdwards),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, ed25519OID), // Required for curve selection
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, labelBytes1),
		pkcs11.NewAttribute(pkcs11.CKA_ID, labelBytes1),
	}

	privateKeyTemplate1 := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, keyTypeECEdwards),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, labelBytes1),
		pkcs11.NewAttribute(pkcs11.CKA_ID, labelBytes1),
	}

	mech1 := []*pkcs11.Mechanism{{Mechanism: mechanismECEdwardsKeyPair, Parameter: nil}}
	_, privHandle1, err1 := a.ctx.GenerateKeyPair(session, mech1, publicKeyTemplate1, privateKeyTemplate1)
	if err1 == nil {
		return fmt.Sprintf("%d", privHandle1), nil
	}
	// Log the error for debugging (method 1 failed)
	log.Debug().Err(err1).Msg("Ed25519 key generation method 1 (CKM_EDDSA) failed, trying method 2")

	// 尝试方法2：使用 CKM_EC_KEY_PAIR_GEN 配合 Ed25519 OID
	// ed25519OID already defined above
	labelBytes2 := []byte(generateLabel())

	publicKeyTemplate2 := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, ed25519OID),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, labelBytes2),
		pkcs11.NewAttribute(pkcs11.CKA_ID, labelBytes2),
	}

	privateKeyTemplate2 := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, labelBytes2),
		pkcs11.NewAttribute(pkcs11.CKA_ID, labelBytes2),
	}

	mech2 := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_EC_KEY_PAIR_GEN, nil)}
	_, privHandle2, err2 := a.ctx.GenerateKeyPair(session, mech2, publicKeyTemplate2, privateKeyTemplate2)
	if err2 == nil {
		return fmt.Sprintf("%d", privHandle2), nil
	}
	// Log both errors for debugging
	log.Debug().Err(err1).Msg("Ed25519 method 1 (CKM_EDDSA) error")
	log.Debug().Err(err2).Msg("Ed25519 method 2 (CKM_EC_KEY_PAIR_GEN with OID) error")

	return "", errors.Wrap(err2, "failed to generate Ed25519 key in SoftHSM; ensure HSM supports Ed25519/EdDSA")
}

// generateAESKey 生成 AES 密钥
//
//nolint:funcorder // generateAESKey is a helper method, should be near GenerateKey
func (a *adapter) generateAESKey(session pkcs11.SessionHandle, keySpec *hsm.KeySpec, keySize int, label string) (pkcs11.ObjectHandle, error) {
	// 生成随机密钥
	keyMaterial := make([]byte, keySize)
	if _, err := rand.Read(keyMaterial); err != nil {
		return 0, errors.Wrap(err, "failed to generate random key material")
	}

	// 创建密钥对象
	labelBytes := []byte(label)
	keyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_AES),
		pkcs11.NewAttribute(pkcs11.CKA_VALUE, keyMaterial),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, labelBytes),
		pkcs11.NewAttribute(pkcs11.CKA_ID, labelBytes),
	}

	handle, err := a.ctx.CreateObject(session, keyTemplate)
	if err != nil {
		return 0, errors.Wrap(err, "failed to create AES key in SoftHSM")
	}

	return handle, nil
}

func getAttributeValue(attrs map[string]string, key string, defaultValue string) string {
	if attrs == nil {
		return defaultValue
	}
	if value, ok := attrs[key]; ok && value != "" {
		return value
	}
	return defaultValue
}

func generateLabel() string {
	return fmt.Sprintf("hsm-key-%d", time.Now().UnixNano())
}

func buildLabelHandle(class, label string) string {
	return fmt.Sprintf("label:%s:%s", class, label)
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

	objHandle, err := a.resolveHandle(session, handle, pkcs11.CKO_PRIVATE_KEY)
	if err != nil {
		return err
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

	objHandle, err := a.resolveHandle(session, handle, pkcs11.CKO_SECRET_KEY)
	if err != nil {
		return nil, err
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

	objHandle, err := a.resolveHandle(session, handle, pkcs11.CKO_SECRET_KEY)
	if err != nil {
		return nil, err
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

	objHandle, err := a.resolveHandle(session, handle, pkcs11.CKO_PRIVATE_KEY)
	if err != nil {
		return nil, err
	}

	// 选择签名机制
	// 注意：digest 已经在调用方计算好了，所以对于 ECDSA 使用 CKM_ECDSA（不是 CKM_ECDSA_SHA256）
	var mech *pkcs11.Mechanism
	switch algorithm {
	case "ECDSA_SHA256", "ECDSA_SHA384", "ECDSA_SHA512":
		// 使用通用的 ECDSA 机制（digest 已在调用方计算）
		mech = pkcs11.NewMechanism(pkcs11.CKM_ECDSA, nil)
	case "ED25519":
		mech = &pkcs11.Mechanism{Mechanism: mechanismEDDSA, Parameter: nil}
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
func (a *adapter) Verify(_ context.Context, handle string, digest []byte, signature []byte, algorithm string) (bool, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	session := a.getSession()
	if session == pkcs11.SessionHandle(0) {
		return false, errors.New("PKCS#11 session not available")
	}

	// 解析私钥句柄以获取标签
	privHandle, err := a.resolveHandle(session, handle, pkcs11.CKO_PRIVATE_KEY)
	if err != nil {
		return false, err
	}

	// 获取私钥的 CKA_ID 或 CKA_LABEL 属性，用于查找对应的公钥
	// 首先尝试获取 CKA_ID
	idAttr := []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_ID, nil)}
	attrs, err := a.ctx.GetAttributeValue(session, privHandle, idAttr)
	if err != nil || len(attrs) == 0 || len(attrs[0].Value) == 0 {
		return false, errors.New("failed to get private key ID attribute for public key lookup")
	}

	// 使用 CKA_ID 查找公钥
	pubKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_ID, attrs[0].Value),
	}
	if err := a.ctx.FindObjectsInit(session, pubKeyTemplate); err != nil {
		return false, errors.Wrap(err, "failed to initialize public key search")
	}

	pubHandles, _, err := a.ctx.FindObjects(session, 1)
	// 立即结束查找操作，释放会话
	if finalErr := a.ctx.FindObjectsFinal(session); finalErr != nil {
		return false, errors.Wrap(finalErr, "failed to finalize public key search")
	}

	if err != nil {
		return false, errors.Wrap(err, "failed to find public key")
	}
	if len(pubHandles) == 0 {
		return false, errors.New("public key not found for verification")
	}

	pubHandle := pubHandles[0]

	// 设置验证机制
	// 注意：digest 已经在调用方计算好了，所以对于 ECDSA 使用 CKM_ECDSA（不是 CKM_ECDSA_SHA256）
	var mech *pkcs11.Mechanism
	switch algorithm {
	case "ECDSA_SHA256", "ECDSA_SHA384", "ECDSA_SHA512":
		// 使用通用的 ECDSA 机制（digest 已在调用方计算）
		mech = pkcs11.NewMechanism(pkcs11.CKM_ECDSA, nil)
	case "ED25519":
		mech = &pkcs11.Mechanism{Mechanism: mechanismEDDSA, Parameter: nil}
	default:
		return false, errors.Errorf("unsupported verification algorithm: %s", algorithm)
	}

	// 初始化验证操作
	if err := a.ctx.VerifyInit(session, []*pkcs11.Mechanism{mech}, pubHandle); err != nil {
		return false, errors.Wrap(err, "failed to initialize verification")
	}

	// 验证签名
	if err := a.ctx.Verify(session, digest, signature); err != nil {
		// PKCS#11 的 Verify 在签名无效时返回错误（CKR_SIGNATURE_INVALID）
		// 我们将其转换为 false 返回值
		if pkcs11Err, ok := err.(pkcs11.Error); ok && pkcs11Err == pkcs11.CKR_SIGNATURE_INVALID {
			return false, nil
		}
		return false, errors.Wrap(err, "failed to verify signature")
	}

	return true, nil
}

func (a *adapter) resolveHandle(session pkcs11.SessionHandle, handle string, defaultClass uint) (pkcs11.ObjectHandle, error) {
	if strings.HasPrefix(handle, "label:") {
		parts := strings.SplitN(handle, ":", 3)
		if len(parts) != 3 {
			return 0, errors.New("invalid label handle format")
		}
		class := classFromString(parts[1], defaultClass)
		label := parts[2]
		return a.findObjectByLabel(session, class, label)
	}

	var objHandle pkcs11.ObjectHandle
	if _, err := fmt.Sscanf(handle, "%d", &objHandle); err != nil {
		return 0, errors.Wrap(err, "invalid key handle")
	}
	return objHandle, nil
}

func classFromString(class string, defaultClass uint) uint {
	switch class {
	case "secret":
		return pkcs11.CKO_SECRET_KEY
	case "private":
		return pkcs11.CKO_PRIVATE_KEY
	case "public":
		return pkcs11.CKO_PUBLIC_KEY
	default:
		return defaultClass
	}
}

func (a *adapter) findObjectByLabel(session pkcs11.SessionHandle, class uint, label string) (pkcs11.ObjectHandle, error) {
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, class),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, []byte(label)),
	}

	if err := a.ctx.FindObjectsInit(session, template); err != nil {
		return 0, errors.Wrap(err, "failed to initialize object search")
	}

	handles, _, err := a.ctx.FindObjects(session, 1)
	if err != nil {
		_ = a.ctx.FindObjectsFinal(session)
		return 0, errors.Wrap(err, "failed to find objects")
	}
	if err := a.ctx.FindObjectsFinal(session); err != nil {
		return 0, errors.Wrap(err, "failed to finalize object search")
	}

	if len(handles) == 0 {
		return 0, errors.Errorf("object with label %s not found", label)
	}

	return handles[0], nil
}

// GetKeyAttributes 获取密钥属性
func (a *adapter) GetKeyAttributes(_ context.Context, handle string) (*hsm.KeyAttributes, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	session := a.getSession()
	if session == pkcs11.SessionHandle(0) {
		return nil, errors.New("PKCS#11 session not available")
	}

	objHandle, err := a.resolveHandle(session, handle, pkcs11.CKO_PRIVATE_KEY)
	if err != nil {
		return nil, err
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
