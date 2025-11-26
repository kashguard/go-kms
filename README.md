# KMS (Key Management Service)

企业级密钥管理服务，基于 go-starter 框架开发，参考 HashiCorp Vault 和 AWS KMS 的架构理念。

## 项目概述

KMS 提供完整的密钥生命周期管理、加密解密、数字签名、访问控制和审计功能，专为 crypto 行业设计。

### 核心功能

- **密钥管理**：创建、查询、更新、删除、轮换密钥
- **加密解密**：对称密钥加密/解密（AES-256-GCM）
- **数字签名**：非对称密钥签名/验证（支持 RAW 和 DIGEST 模式）
- **访问控制**：基于策略的权限管理
- **审计日志**：完整的操作审计追踪
- **HSM 集成**：完整的 PKCS#11 支持，包括 SoftHSM 和硬件 HSM
- **Secret 存储**：安全的密钥-值存储（使用 KMS 密钥加密）

### 支持的密钥类型

| 密钥类型 | 用途 | 特点 |
|---------|------|------|
| **AES-256** | 对称加密 | 高性能数据加密，支持信封加密 |
| **ECC secp256k1** | 数字签名 | Bitcoin/Ethereum 标准曲线 |
| **ECC P-256** | 数字签名 | NIST 标准椭圆曲线 |
| **Ed25519** | 数字签名 | 现代高性能签名算法，更小的密钥和签名 ✨ |

> ✨ **Ed25519 完全支持**：通过自定义编译的 OpenSSL 3.2.2 和 SoftHSM 2.6.1 实现完整的 Ed25519 支持，包括密钥生成、签名和验证。

## 快速开始

### 环境要求

- Go 1.21+
- PostgreSQL 14+
- Docker & Docker Compose（推荐用于本地开发）
- SoftHSM 2.6.1+ 或兼容的 PKCS#11 HSM

### Docker 快速启动（推荐）

```bash
# 克隆仓库
git clone <repository-url>
cd go-kms

# 启动所有服务（包括 PostgreSQL 和 SoftHSM）
docker compose up -d

# 查看服务状态
docker compose ps

# 查看日志
docker compose logs -f service
```

服务将在 `http://localhost:8080` 启动。

### 本地开发配置

设置环境变量：

```bash
# 数据库配置
export PGHOST=localhost
export PGPORT=5432
export PGDATABASE=kms
export PGUSER=dbuser
export PGPASSWORD=your_password

# KMS 配置
export KMS_STORAGE_BACKEND=postgresql
export KMS_HSM_TYPE=software

# HSM 配置（自动检测，可选）
# export KMS_HSM_LIBRARY=/home/development/softhsm-ed25519/lib/softhsm/libsofthsm2.so
# export KMS_HSM_SLOT=0
export KMS_HSM_PIN=1234
export KMS_HSM_LABEL=KMS

# 功能开关
export KMS_ENABLE_AUDIT=true
export KMS_ENABLE_POLICY=true
export KMS_ENABLE_SECRET_SERVICE=true
export KMS_SECRET_KEY_ID=<your-key-id>  # Secret 服务加密密钥
```

### 本地运行

```bash
# 应用数据库迁移
make sql-reset

# 启动服务
make run
```

### Ed25519 支持

本项目包含自定义编译的 OpenSSL 3.2.2 和 SoftHSM 2.6.1 以支持 Ed25519：

```bash
# 构建支持 Ed25519 的 SoftHSM（在 Docker 容器内自动执行）
./scripts/build-softhsm-ed25519.sh

# 验证 SoftHSM 库
ldd /home/development/softhsm-ed25519/lib/softhsm/libsofthsm2.so | grep crypto
# 应该显示链接到自定义 OpenSSL: /home/development/openssl-ed25519/lib/libcrypto.so.3
```

### API 文档

- **Swagger UI**: `http://localhost:8080/swagger-ui/`
- **健康检查**: `http://localhost:8080/-/healthy`
- **API 版本**: `http://localhost:8080/api/v1/`

## API 使用示例

### 1. 用户认证

```bash
# 注册用户
curl -X POST http://localhost:8080/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "user@example.com",
    "password": "your-secure-password"
  }'

# 登录获取 token
TOKEN=$(curl -s -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "user@example.com",
    "password": "your-secure-password"
  }' | jq -r '.access_token')
```

### 2. 创建密钥

```bash
# 创建 AES-256 密钥（用于加密）
curl -X POST http://localhost:8080/api/v1/kms/keys \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "key_type": "AES_256",
    "alias": "my-encryption-key",
    "description": "用于数据加密"
  }'

# 创建 Ed25519 密钥（用于签名）
curl -X POST http://localhost:8080/api/v1/kms/keys \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "key_type": "ED25519",
    "alias": "my-signing-key",
    "description": "用于数字签名"
  }'
```

### 3. 加密和解密

```bash
# 加密数据
CIPHERTEXT=$(curl -s -X POST http://localhost:8080/api/v1/kms/encrypt \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "key_id": "key-xxx",
    "plaintext": "'$(echo -n "Hello, KMS!" | base64)'"
  }' | jq -r '.ciphertext_blob')

# 解密数据
curl -X POST http://localhost:8080/api/v1/kms/decrypt \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{
    \"ciphertext_blob\": \"$CIPHERTEXT\"
  }"
```

### 4. 签名和验证

```bash
# 使用 Ed25519 签名
SIGNATURE=$(curl -s -X POST http://localhost:8080/api/v1/kms/sign \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "key_id": "key-xxx",
    "message": "'$(echo -n "Message to sign" | base64)'",
    "message_type": "RAW",
    "algorithm": "ED25519"
  }' | jq -r '.signature')

# 验证签名
curl -X POST http://localhost:8080/api/v1/kms/verify \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{
    \"key_id\": \"key-xxx\",
    \"message\": \"$(echo -n 'Message to sign' | base64)\",
    \"message_type\": \"RAW\",
    \"signature\": \"$SIGNATURE\",
    \"algorithm\": \"ED25519\"
  }"
```

### 5. 密钥管理

```bash
# 列出所有密钥
curl -X GET http://localhost:8080/api/v1/kms/keys \
  -H "Authorization: Bearer $TOKEN"

# 获取密钥详情
curl -X GET http://localhost:8080/api/v1/kms/keys/key-xxx \
  -H "Authorization: Bearer $TOKEN"

# 禁用密钥
curl -X POST http://localhost:8080/api/v1/kms/keys/key-xxx/disable \
  -H "Authorization: Bearer $TOKEN"

# 启用密钥
curl -X POST http://localhost:8080/api/v1/kms/keys/key-xxx/enable \
  -H "Authorization: Bearer $TOKEN"

# 轮换密钥
curl -X POST http://localhost:8080/api/v1/kms/keys/key-xxx/rotate \
  -H "Authorization: Bearer $TOKEN"
```

更多 API 使用示例和测试脚本请参考：
- [KMS API 测试计划](docs/KMS-API-接口测试计划.md)
- [API 使用示例](docs/KMS-API-使用示例.md)

## 项目结构

```
internal/kms/
├── key/          # 密钥管理服务
├── encryption/   # 加密解密服务
├── sign/         # 签名验证服务
├── policy/       # 策略引擎
├── audit/        # 审计日志
├── storage/      # 存储抽象层
└── hsm/          # HSM 适配器
    └── software/ # SoftHSM 实现
```

## 开发指南

### 构建

```bash
make build       # 完整构建（sql + swagger + go-build + lint）
make all         # 完整构建 + 测试
make go-build    # 仅编译 Go 代码
make go-lint     # 运行 golangci-lint
```

### 测试

```bash
make test        # 运行所有测试
make watch-tests # 监听文件变化自动运行测试

# 运行完整的 API 测试
./scripts/test-kms-api.sh
```

### 数据库开发

```bash
make sql         # 生成 SQLBoiler 模型（从 migrations/）
make sql-reset   # 重置开发数据库
make watch-sql   # 监听 SQL 文件变化
```

### API 开发

```bash
make swagger       # 生成 Swagger 代码（从 api/）
make watch-swagger # 监听 API 文件变化
```

### HSM 开发

```bash
# 构建支持 Ed25519 的 SoftHSM
./scripts/build-softhsm-ed25519.sh

# 初始化 SoftHSM
./scripts/init-softhsm.sh

# 查看 SoftHSM slots
softhsm2-util --show-slots
```

### 代码规范

本项目遵循以下开发规范：
- **Wire 依赖注入**：所有服务使用 Wire 进行依赖注入
- **Swagger-First API**：先定义 API 规范，再实现 Handler
- **SQLBoiler ORM**：数据库操作使用 SQLBoiler 生成的模型
- **分层架构**：Handler → Service → Model → Persistence
- **错误处理**：使用 `github.com/pkg/errors` 包装错误
- **日志记录**：使用 zerolog 结构化日志

详细规范请查看 [.cursorrules](.cursorrules)

## 技术架构

### PKCS#11 机制映射

| 操作 | 密钥类型 | PKCS#11 机制 | 说明 |
|-----|---------|-------------|-----|
| 密钥生成 | AES-256 | CKM_AES_KEY_GEN | 生成 256-bit AES 密钥 |
| 密钥生成 | ECC (secp256k1/P-256) | CKM_EC_KEY_PAIR_GEN | 生成 EC 密钥对 |
| 密钥生成 | Ed25519 | CKM_EC_EDWARDS_KEY_PAIR_GEN | 生成 Ed25519 密钥对 |
| 加密/解密 | AES-256 | CKM_AES_GCM | AES-GCM 模式 |
| 签名/验证 | ECC | CKM_ECDSA | ECDSA 签名（摘要已预计算） |
| 签名/验证 | Ed25519 | CKM_EDDSA | EdDSA 签名 |

### 依赖版本

- **Go**: 1.21+
- **PostgreSQL**: 17.4
- **OpenSSL**: 3.2.2 (自定义编译，支持 Ed25519)
- **SoftHSM**: 2.6.1 (自定义编译，启用 EdDSA)
- **go-starter**: 最新版本

### 安全特性

- ✅ **零信任架构**：所有请求都需要认证和授权
- ✅ **密钥永不离开 HSM**：所有密钥操作在 HSM 内执行
- ✅ **策略引擎**：细粒度的访问控制
- ✅ **审计日志**：不可篡改的操作记录
- ✅ **加密上下文**：防止密钥滥用
- ✅ **密钥轮换**：支持自动和手动轮换
- ✅ **TLS 通信**：生产环境强制 HTTPS

## 文档

### 产品文档
- [产品架构](docs/KMS产品文档/01-产品架构.md)
- [密钥管理](docs/KMS产品文档/02-密钥管理.md)
- [加密服务](docs/KMS产品文档/03-加密服务.md)
- [签名验证](docs/KMS产品文档/04-签名验证.md)
- [API 参考](docs/KMS产品文档/05-API参考.md)

### 开发文档
- [开发计划](docs/KMS开发计划.md)
- [API 测试计划](docs/KMS-API-接口测试计划.md)
- [API 使用示例](docs/KMS-API-使用示例.md)
- [服务器初始化](docs/server-initialization.md)
- [Secret 存储服务](docs/Secret存储服务实现计划.md)

### 脚本说明
- [脚本文档](scripts/README.md)
- [Ed25519 构建脚本](scripts/build-softhsm-ed25519.sh)
- [SoftHSM 初始化](scripts/init-softhsm.sh)

## 更新日志

查看 [CHANGELOG.md](CHANGELOG.md) 了解最新的功能更新和修复。

## 许可证

本项目基于 MIT 许可证。查看 [LICENSE](LICENSE) 文件了解详情。

## 基于 go-starter

本项目基于 [go-starter](https://github.com/allaboutapps/go-starter) 框架开发。更多关于 go-starter 的信息，请查看 [README-go-starter.md](README-go-starter.md)。

## 贡献

欢迎贡献！请查看我们的开发规范：
1. Fork 本仓库
2. 创建功能分支 (`git checkout -b feature/amazing-feature`)
3. 提交更改 (`git commit -m 'Add amazing feature'`)
4. 推送到分支 (`git push origin feature/amazing-feature`)
5. 创建 Pull Request

## 支持

如有问题或建议，请：
- 提交 [Issue](https://github.com/your-org/go-kms/issues)
- 查看 [文档](docs/)
- 联系维护团队