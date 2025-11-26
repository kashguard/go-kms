# KMS API 测试快速开始指南

## 快速开始

### 1. 确保服务器运行

```bash
# 在 Docker 容器中启动服务器
docker-compose up -d

# 或者直接运行
app server
```

### 2. 运行完整测试套件

```bash
# 运行所有测试（推荐）
./tests/test-all.sh

# 显示详细输出
./tests/test-all.sh -v

# 指定 API URL
./tests/test-all.sh -u http://localhost:8080
```

### 3. 运行单个测试

```bash
# 只测试认证流程
./tests/test-auth.sh

# 只测试密钥管理
./tests/test-keys.sh

# 只测试加密解密
./tests/test-encryption.sh
```

## 测试顺序

如果手动运行单个测试，请按以下顺序：

1. `test-auth.sh` - 必须先运行，获取 token
2. `test-keys.sh` - 创建密钥
3. `test-encryption.sh` - 测试加密（需要 AES 密钥）
4. `test-signing.sh` - 测试签名（需要签名密钥）
5. `test-policies.sh` - 测试策略管理
6. `test-audit.sh` - 测试审计日志
7. `test-errors.sh` - 测试错误场景

## 测试输出

每个测试脚本会输出：
- ✓ PASSED - 测试通过（绿色）
- ✗ FAILED - 测试失败（红色）
- 测试耗时（毫秒）
- 测试总结

## 测试数据存储

测试过程中会创建以下临时文件：
- `/tmp/kms_test_token.txt` - 访问 token
- `/tmp/kms_test_refresh_token.txt` - 刷新 token
- `/tmp/kms_test_key_ids.txt` - 密钥 ID 列表
- `/tmp/kms_test_ciphertext.txt` - 加密后的数据
- `/tmp/kms_test_signature_secp256k1.txt` - 签名数据

这些文件会在测试之间共享，方便后续测试使用。

## 常见问题

### Q: Token 文件不存在
A: 先运行 `test-auth.sh` 获取 token

### Q: Key IDs 文件不存在
A: 先运行 `test-keys.sh` 创建密钥

### Q: 连接错误
A: 检查服务器是否运行，BASE_URL 是否正确

### Q: 401 认证错误
A: Token 可能已过期，重新运行 `test-auth.sh`

