# KMS API 测试脚本

本目录包含 KMS API 的完整测试脚本，用于验证所有 API 接口的功能。

## 测试脚本列表

1. **test-auth.sh** - 用户认证流程测试
   - 用户注册
   - 用户登录
   - Token 刷新

2. **test-keys.sh** - 密钥管理测试
   - 创建各种类型的密钥（AES_256, ECC_SECP256K1, ECC_P256, ED25519）
   - 获取密钥详情
   - 列出所有密钥
   - 更新密钥
   - 启用/禁用密钥
   - 轮换密钥

3. **test-encryption.sh** - 加密解密测试
   - 数据加密
   - 数据解密
   - 数据密钥生成（信封加密）

4. **test-signing.sh** - 签名验证测试
   - ECC_SECP256K1 签名和验证（RAW 模式）
   - ED25519 签名（RAW 模式）
   - ECC_P256 签名（DIGEST 模式）

5. **test-policies.sh** - 策略管理测试
   - 创建策略
   - 获取策略
   - 列出所有策略
   - 更新策略
   - 删除策略

6. **test-audit.sh** - 审计日志测试
   - 查询审计日志
   - 按时间范围查询
   - 按密钥ID查询

7. **test-errors.sh** - 错误场景测试
   - 未认证访问
   - 无效 token
   - 资源不存在
   - 使用禁用的密钥
   - 错误的加密上下文
   - 无效的签名验证
   - Secret 服务未启用
   - 无效的密钥类型
   - 无效的算法

8. **test-all.sh** - 完整测试套件
   - 按顺序运行所有测试脚本
   - 生成测试总结报告

## 使用方法

### 运行单个测试脚本

```bash
# 运行认证测试
./tests/test-auth.sh

# 运行密钥管理测试
./tests/test-keys.sh

# 显示详细输出
./tests/test-keys.sh -v

# 指定 API 基础 URL
./tests/test-keys.sh -u http://localhost:8080
```

### 运行完整测试套件

```bash
# 运行所有测试
./tests/test-all.sh

# 显示详细输出
./tests/test-all.sh -v

# 指定 API 基础 URL
./tests/test-all.sh -u http://localhost:8080
```

## 环境变量

测试脚本使用以下环境变量和文件：

- `BASE_URL` - API 基础 URL（默认: http://localhost:8080）
- `TOKEN_FILE` - Token 存储文件（默认: /tmp/kms_test_token.txt）
- `REFRESH_TOKEN_FILE` - Refresh Token 存储文件（默认: /tmp/kms_test_refresh_token.txt）
- `KEY_IDS_FILE` - Key IDs 存储文件（默认: /tmp/kms_test_key_ids.txt）
- `CIPHERTEXT_FILE` - 密文存储文件（默认: /tmp/kms_test_ciphertext.txt）
- `SIGNATURE_FILE` - 签名存储文件（默认: /tmp/kms_test_signature_secp256k1.txt）

## 测试依赖关系

测试脚本需要按以下顺序运行：

1. `test-auth.sh` - 必须先运行，获取 token
2. `test-keys.sh` - 创建密钥，供后续测试使用
3. `test-encryption.sh` - 依赖 `test-keys.sh` 创建的 AES 密钥
4. `test-signing.sh` - 依赖 `test-keys.sh` 创建的签名密钥
5. `test-policies.sh` - 独立测试
6. `test-audit.sh` - 可以独立运行，但需要先有操作记录
7. `test-errors.sh` - 可以独立运行，但某些测试需要先创建密钥

使用 `test-all.sh` 会自动按正确顺序运行所有测试。

## 测试结果

每个测试脚本会输出：
- ✓ PASSED - 测试通过
- ✗ FAILED - 测试失败
- 测试耗时（毫秒）
- 测试总结（通过/失败数量）

## 注意事项

1. 确保服务器已启动并运行在指定端口
2. 确保 SoftHSM 已正确初始化
3. 确保数据库已迁移完成
4. Secret 服务当前未启用，相关测试会返回 503 错误（这是预期的）
5. 某些测试会修改密钥状态（如禁用/启用），测试后会自动恢复

## 故障排除

### Token 文件不存在
如果遇到 "Token 文件不存在" 错误，请先运行 `test-auth.sh`。

### Key IDs 文件不存在
如果遇到 "Key IDs 文件不存在" 错误，请先运行 `test-keys.sh`。

### 连接错误
如果遇到连接错误，请检查：
- 服务器是否正在运行
- BASE_URL 是否正确
- 防火墙设置

### 认证错误
如果遇到 401 错误，请检查：
- Token 是否有效
- Token 是否已过期
- 用户是否已正确注册和登录

