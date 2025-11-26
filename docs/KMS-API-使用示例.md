# KMS API 使用示例

本文档提供 KMS API 的使用示例，帮助开发者快速集成 KMS 服务。

## 认证

所有 KMS API 都需要 Bearer Token 认证：

```bash
Authorization: Bearer <access_token>
```

## 密钥管理

### 创建密钥

创建 AES-256 对称密钥：

```bash
curl -X POST http://localhost:8080/api/v1/kms/keys \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "key_type": "AES_256",
    "alias": "my-encryption-key",
    "description": "用于生产环境数据加密",
    "tags": {
      "environment": "production",
      "team": "backend"
    }
  }'
```

创建 ECC secp256k1 密钥（用于 Bitcoin/Ethereum）：

```bash
curl -X POST http://localhost:8080/api/v1/kms/keys \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "key_type": "ECC_SECP256K1",
    "alias": "bitcoin-signing-key",
    "description": "用于 Bitcoin 交易签名"
  }'
```

创建 Ed25519 密钥：

```bash
curl -X POST http://localhost:8080/api/v1/kms/keys \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "key_type": "ED25519",
    "alias": "ed25519-key",
    "description": "高性能签名密钥"
  }'
```

### 查询密钥

```bash
curl -X GET http://localhost:8080/api/v1/kms/keys/{keyId} \
  -H "Authorization: Bearer <token>"
```

### 列出密钥

```bash
curl -X GET "http://localhost:8080/api/v1/kms/keys?state=Enabled&limit=10&offset=0" \
  -H "Authorization: Bearer <token>"
```

### 更新密钥

```bash
curl -X PUT http://localhost:8080/api/v1/kms/keys/{keyId} \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "description": "更新后的描述",
    "tags": {
      "environment": "production",
      "updated": "2025-11-26"
    }
  }'
```

### 启用/禁用密钥

```bash
# 启用密钥
curl -X POST http://localhost:8080/api/v1/kms/keys/{keyId}/enable \
  -H "Authorization: Bearer <token>"

# 禁用密钥
curl -X POST http://localhost:8080/api/v1/kms/keys/{keyId}/disable \
  -H "Authorization: Bearer <token>"
```

### 轮换密钥

```bash
curl -X POST http://localhost:8080/api/v1/kms/keys/{keyId}/rotate \
  -H "Authorization: Bearer <token>"
```

### 删除密钥

```bash
curl -X DELETE http://localhost:8080/api/v1/kms/keys/{keyId} \
  -H "Authorization: Bearer <token>"
```

## 加密解密

### 加密数据

```bash
# 将明文进行 base64 编码
PLAINTEXT=$(echo -n "Hello, World!" | base64)

curl -X POST http://localhost:8080/api/v1/kms/encrypt \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d "{
    \"key_id\": \"key-1234567890abcdef\",
    \"plaintext\": \"$PLAINTEXT\",
    \"encryption_context\": {
      \"purpose\": \"database_encryption\",
      \"table\": \"users\"
    }
  }"
```

响应示例：

```json
{
  "ciphertext_blob": "AQICAHi...",
  "key_id": "key-1234567890abcdef",
  "key_version": 1
}
```

### 解密数据

```bash
curl -X POST http://localhost:8080/api/v1/kms/decrypt \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "ciphertext_blob": "AQICAHi...",
    "encryption_context": {
      "purpose": "database_encryption",
      "table": "users"
    }
  }'
```

### 生成数据密钥（信封加密）

```bash
curl -X POST http://localhost:8080/api/v1/kms/generate-data-key \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "key_id": "key-1234567890abcdef",
    "key_spec": "AES_256",
    "number_of_bytes": 32,
    "return_plaintext": true,
    "encryption_context": {
      "purpose": "file_encryption"
    }
  }'
```

## 签名验证

### 签名数据

使用 DIGEST 模式（推荐）：

```bash
# 将消息进行 base64 编码
MESSAGE=$(echo -n "Transaction data" | base64)

curl -X POST http://localhost:8080/api/v1/kms/sign \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d "{
    \"key_id\": \"key-1234567890abcdef\",
    \"message\": \"$MESSAGE\",
    \"algorithm\": \"ECDSA_SHA256\",
    \"mode\": \"DIGEST\"
  }"
```

使用 RAW 模式：

```bash
curl -X POST http://localhost:8080/api/v1/kms/sign \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d "{
    \"key_id\": \"key-1234567890abcdef\",
    \"message\": \"$MESSAGE\",
    \"algorithm\": \"ECDSA_SHA256\",
    \"mode\": \"RAW\"
  }"
```

### 验证签名

```bash
curl -X POST http://localhost:8080/api/v1/kms/verify \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d "{
    \"key_id\": \"key-1234567890abcdef\",
    \"message\": \"$MESSAGE\",
    \"signature\": \"MEUCIQD...\",
    \"algorithm\": \"ECDSA_SHA256\",
    \"mode\": \"DIGEST\"
  }"
```

## Go SDK 示例

```go
package main

import (
    "context"
    "encoding/base64"
    "fmt"
    "net/http"
    
    "github.com/go-resty/resty/v2"
)

func main() {
    client := resty.New().
        SetBaseURL("http://localhost:8080/api/v1/kms").
        SetAuthToken("your-access-token").
        SetHeader("Content-Type", "application/json")
    
    ctx := context.Background()
    
    // 创建密钥
    createResp := struct {
        KeyID    string `json:"key_id"`
        KeyType  string `json:"key_type"`
        KeyState string `json:"key_state"`
    }{}
    
    _, err := client.R().
        SetContext(ctx).
        SetBody(map[string]interface{}{
            "key_type": "AES_256",
            "alias":    "my-key",
        }).
        SetResult(&createResp).
        Post("/keys")
    
    if err != nil {
        panic(err)
    }
    
    fmt.Printf("Created key: %s\n", createResp.KeyID)
    
    // 加密数据
    plaintext := []byte("Hello, World!")
    plaintextB64 := base64.StdEncoding.EncodeToString(plaintext)
    
    encryptResp := struct {
        CiphertextBlob string `json:"ciphertext_blob"`
        KeyID         string `json:"key_id"`
    }{}
    
    _, err = client.R().
        SetContext(ctx).
        SetBody(map[string]interface{}{
            "key_id":    createResp.KeyID,
            "plaintext": plaintextB64,
        }).
        SetResult(&encryptResp).
        Post("/encrypt")
    
    if err != nil {
        panic(err)
    }
    
    fmt.Printf("Encrypted: %s\n", encryptResp.CiphertextBlob)
    
    // 解密数据
    decryptResp := struct {
        Plaintext string `json:"plaintext"`
    }{}
    
    _, err = client.R().
        SetContext(ctx).
        SetBody(map[string]interface{}{
            "ciphertext_blob": encryptResp.CiphertextBlob,
        }).
        SetResult(&decryptResp).
        Post("/decrypt")
    
    if err != nil {
        panic(err)
    }
    
    decrypted, _ := base64.StdEncoding.DecodeString(decryptResp.Plaintext)
    fmt.Printf("Decrypted: %s\n", string(decrypted))
}
```

## Python SDK 示例

```python
import requests
import base64

BASE_URL = "http://localhost:8080/api/v1/kms"
TOKEN = "your-access-token"

headers = {
    "Authorization": f"Bearer {TOKEN}",
    "Content-Type": "application/json"
}

# 创建密钥
response = requests.post(
    f"{BASE_URL}/keys",
    headers=headers,
    json={
        "key_type": "AES_256",
        "alias": "my-key"
    }
)
key_data = response.json()
key_id = key_data["key_id"]
print(f"Created key: {key_id}")

# 加密数据
plaintext = "Hello, World!"
plaintext_b64 = base64.b64encode(plaintext.encode()).decode()

response = requests.post(
    f"{BASE_URL}/encrypt",
    headers=headers,
    json={
        "key_id": key_id,
        "plaintext": plaintext_b64
    }
)
encrypt_data = response.json()
ciphertext = encrypt_data["ciphertext_blob"]
print(f"Encrypted: {ciphertext}")

# 解密数据
response = requests.post(
    f"{BASE_URL}/decrypt",
    headers=headers,
    json={
        "ciphertext_blob": ciphertext
    }
)
decrypt_data = response.json()
decrypted_b64 = decrypt_data["plaintext"]
decrypted = base64.b64decode(decrypted_b64).decode()
print(f"Decrypted: {decrypted}")
```

## 错误处理

所有 API 错误都遵循统一的错误格式：

```json
{
  "code": 400,
  "type": "generic",
  "title": "Bad Request",
  "detail": "Invalid key type"
}
```

验证错误格式：

```json
{
  "code": 400,
  "type": "validation",
  "title": "Validation Error",
  "validation_errors": [
    {
      "key": "key_type",
      "in": "body",
      "error": "must be one of: ECC_SECP256K1, ECC_P256, ED25519, AES_256"
    }
  ]
}
```

## 最佳实践

1. **密钥管理**：
   - 定期轮换密钥
   - 使用有意义的别名和标签
   - 为不同环境使用不同的密钥

2. **加密上下文**：
   - 始终使用加密上下文防止密钥滥用
   - 加密和解密时使用相同的上下文

3. **错误处理**：
   - 检查所有 API 响应的状态码
   - 处理网络错误和超时
   - 记录所有加密操作（不记录敏感数据）

4. **性能优化**：
   - 缓存密钥元数据（不缓存密钥本身）
   - 使用连接池
   - 批量操作时考虑限流

5. **安全建议**：
   - 使用 HTTPS 传输
   - 定期审查审计日志
   - 限制密钥访问权限
   - 使用策略引擎控制访问

