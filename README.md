# KMS (Key Management Service)

企业级密钥管理服务，基于 go-starter 框架开发，参考 HashiCorp Vault 和 AWS KMS 的架构理念。

## 项目概述

KMS 提供完整的密钥生命周期管理、加密解密、数字签名、访问控制和审计功能，专为 crypto 行业设计。

### 核心功能

- **密钥管理**：创建、查询、更新、删除、轮换密钥
- **加密解密**：对称密钥加密/解密（AES-256）
- **数字签名**：非对称密钥签名/验证（ECC secp256k1、P-256、Ed25519）
- **访问控制**：基于策略的权限管理
- **审计日志**：完整的操作审计追踪
- **HSM 集成**：支持 SoftHSM 和 PKCS#11 标准硬件 HSM

### 支持的密钥类型

- **ECC secp256k1**：Bitcoin/Ethereum 签名
- **ECC P-256**：通用标准椭圆曲线
- **Ed25519**：现代高性能签名算法
- **AES-256**：对称加密

## 快速开始

### 环境要求

- Go 1.21+
- PostgreSQL 14+
- Docker & Docker Compose（用于本地开发）

### 配置

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
export KMS_HSM_LIBRARY=/usr/lib/softhsm/libsofthsm2.so
export KMS_HSM_SLOT=0
export KMS_HSM_PIN=1234
export KMS_ENABLE_AUDIT=true
export KMS_ENABLE_POLICY=true
```

### 运行

```bash
# 应用数据库迁移
make sql-reset

# 启动服务
go run main.go server
```

服务将在 `http://localhost:8080` 启动。

### API 文档

访问 Swagger UI：`http://localhost:8080/swagger-ui/`

## API 使用

### 创建密钥

```bash
curl -X POST http://localhost:8080/api/v1/kms/keys \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "key_type": "AES_256",
    "alias": "my-encryption-key"
  }'
```

### 加密数据

```bash
curl -X POST http://localhost:8080/api/v1/kms/encrypt \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "key_id": "key-123",
    "plaintext": "SGVsbG8gV29ybGQ="
  }'
```

更多 API 使用示例请参考 [KMS API 使用示例](docs/KMS-API-使用示例.md)

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

## 开发

### 构建

```bash
make build    # 完整构建（sql + swagger + go-build + lint）
make all      # 完整构建 + 测试
```

### 测试

```bash
make test     # 运行所有测试
```

### 数据库迁移

```bash
make sql      # 生成 SQLBoiler 模型
make sql-reset # 重置开发数据库
```

### API 开发

```bash
make swagger  # 生成 Swagger 代码
```

## 文档

- [开发计划](docs/KMS开发计划.md)
- [API 使用示例](docs/KMS-API-使用示例.md)
- [服务器初始化](docs/server-initialization.md)

## 基于 go-starter

本项目基于 [go-starter](https://github.com/allaboutapps/go-starter) 框架开发。更多关于 go-starter 的信息，请查看 [README-go-starter.md](README-go-starter.md)。