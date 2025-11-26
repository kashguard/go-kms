# `/internal` - KMS 内部代码目录

本目录包含 KMS（密钥管理服务）的私有应用和库代码。这些代码不应被其他应用程序或库导入。此布局模式由 Go 编译器强制执行。详见 [Go 1.4 发布说明](https://golang.org/doc/go1.4#internalpackages)。

## 产品概述

KMS（Key Management Service）是一个企业级密钥管理服务系统，基于 go-starter 框架开发，参考 HashiCorp Vault 和 AWS KMS 的架构理念。系统提供完整的密钥生命周期管理、加密解密、数字签名、访问控制和审计功能，专为 crypto 行业设计。

### 核心设计原则

1. **密钥安全**：密钥在 HSM 内生成和存储，密钥永不离开 HSM 未加密状态
2. **存储抽象**：支持多种存储后端（PostgreSQL、Consul、文件系统等）
3. **认证抽象**：支持多种认证方式（Token、AppRole、LDAP、OAuth 等）
4. **策略引擎**：基于策略的访问控制（Policy-Based Access Control）
5. **审计追踪**：所有操作记录不可篡改的审计日志
6. **零信任架构**：不信任任何请求，所有请求都需要验证

## 实现功能

### 1. 密钥管理服务 (`/internal/kms/key`)

提供完整的密钥生命周期管理：

- **密钥创建**：在 HSM 内生成密钥，支持多种密钥类型
- **密钥查询**：根据密钥 ID 或别名查询密钥元数据
- **密钥更新**：更新密钥描述、标签等元数据
- **密钥删除**：软删除机制，支持删除等待期
- **密钥轮换**：创建新版本密钥，保留旧版本用于解密历史数据
- **密钥启用/禁用**：控制密钥的使用状态
- **密钥版本管理**：支持多版本密钥，主版本用于新操作

**支持的密钥类型**：
- **ECC secp256k1**：Bitcoin/Ethereum 签名
- **ECC P-256**：通用标准椭圆曲线
- **Ed25519**：现代高性能签名算法
- **AES-256**：对称加密

### 2. 加密解密服务 (`/internal/kms/encryption`)

提供对称密钥加密/解密功能：

- **数据加密**：使用 KMS 密钥加密数据
- **数据解密**：使用 KMS 密钥解密数据
- **数据密钥生成**：信封加密（Envelope Encryption），生成数据加密密钥（DEK）
- **加密上下文验证**：防止密钥滥用，确保加密上下文一致性

### 3. 签名验证服务 (`/internal/kms/sign`)

提供数字签名和验证功能：

- **数字签名**：使用私钥对数据进行签名
- **签名验证**：使用公钥验证签名
- **支持模式**：
  - **RAW 模式**：直接对原始数据进行签名
  - **DIGEST 模式**：对消息摘要进行签名

**支持的签名算法**：
- ECDSA（secp256k1、P-256）
- Ed25519

### 4. 策略引擎 (`/internal/kms/policy`)

基于策略的访问控制：

- **策略定义**：JSON 格式的策略文档
- **策略评估**：实时评估用户权限
- **细粒度控制**：支持 create、read、update、delete、use 等操作权限
- **拒绝优先**：Deny 策略优先于 Allow 策略

### 5. 审计日志 (`/internal/kms/audit`)

完整的操作审计追踪：

- **事件记录**：所有密钥操作、访问尝试
- **日志查询**：支持按时间、用户、密钥等条件查询
- **不可篡改**：审计日志独立存储，加密保存
- **合规支持**：满足金融、医疗等行业的合规要求

### 6. Secret 存储服务 (`/internal/kms/secret`)

加密存储用户数据：

- **Secret 创建**：使用 KMS 密钥加密存储用户数据（如 keystore JSON）
- **Secret 查询**：解密并返回用户数据
- **Secret 更新**：更新加密存储的数据
- **Secret 删除**：安全删除 Secret
- **Secret 存在性检查**：检查 Secret 是否存在

### 7. HSM 适配器 (`/internal/kms/hsm`)

硬件安全模块抽象层：

- **PKCS#11 接口**：标准 HSM 接口
- **SoftHSM 实现**：软件 HSM，用于开发和测试
- **硬件 HSM 支持**：可适配各种 PKCS#11 兼容的硬件 HSM
- **密钥操作**：密钥生成、加密、解密、签名、验证

### 8. 存储抽象层 (`/internal/kms/storage`)

元数据存储抽象：

- **PostgreSQL 实现**：使用 SQLBoiler 进行数据库操作
- **存储接口**：支持多种存储后端（PostgreSQL、Consul、文件系统等）
- **数据模型**：密钥元数据、密钥版本、策略、审计日志、Secret

## 使用场景

### 1. 加密货币钱包

- **密钥管理**：安全存储和管理钱包私钥
- **交易签名**：使用私钥对交易进行签名
- **密钥轮换**：定期轮换密钥，提高安全性
- **审计追踪**：记录所有密钥操作，满足合规要求

### 2. 企业数据加密

- **数据加密**：使用 KMS 密钥加密敏感数据
- **密钥管理**：集中管理所有加密密钥
- **访问控制**：基于策略控制密钥使用权限
- **合规审计**：完整的操作审计日志

### 3. API 密钥管理

- **密钥生成**：为不同服务生成独立的 API 密钥
- **密钥轮换**：定期轮换 API 密钥
- **权限控制**：基于策略控制 API 密钥的使用范围
- **使用追踪**：记录所有 API 密钥的使用情况

### 4. 数字签名服务

- **文档签名**：对重要文档进行数字签名
- **签名验证**：验证文档签名的有效性
- **签名审计**：记录所有签名操作
- **密钥管理**：安全管理签名密钥

### 5. 托管钱包服务

- **Secret 存储**：加密存储用户的 keystore JSON
- **密钥管理**：管理托管钱包的加密密钥
- **安全访问**：基于策略控制 Secret 访问权限
- **审计日志**：记录所有 Secret 操作

## 目录结构

### `/internal/api`

API 实现和服务器配置：

- `/internal/api/handlers/kms/` - KMS API 处理器
  - `keys/` - 密钥管理 API
  - `encryption/` - 加密解密 API
  - `sign/` - 签名验证 API
  - `policies/` - 策略管理 API
  - `audit/` - 审计日志 API
  - `secrets/` - Secret 存储 API
- `/internal/api/server.go` - 服务器结构体
- `/internal/api/router/` - 路由配置
- `/internal/api/middleware/` - 中间件（认证、日志、错误处理等）

### `/internal/kms`

KMS 核心服务层：

- `/internal/kms/key/` - 密钥管理服务
- `/internal/kms/encryption/` - 加密解密服务
- `/internal/kms/sign/` - 签名验证服务
- `/internal/kms/policy/` - 策略引擎
- `/internal/kms/audit/` - 审计日志
- `/internal/kms/secret/` - Secret 存储服务
- `/internal/kms/hsm/` - HSM 适配器
  - `software/` - SoftHSM 实现
- `/internal/kms/storage/` - 存储抽象层
  - `postgresql.go` - PostgreSQL 实现

### `/internal/config`

项目配置管理：

- `/internal/config/server_config.go` - 服务器配置（包含 KMS 配置）
- `/internal/config/db_config.go` - 数据库配置

### `/internal/data`

数据相关代码：

- `/internal/data/dto/` - 数据传输对象
- `/internal/data/mapper/` - 数据映射器
- `/internal/data/fixtures/` - 测试数据

### `/internal/models`

> **自动生成** [SQLBoiler](https://github.com/volatiletech/sqlboiler#getting-started) 模型。**不要**在此目录放置自己的文件。

这些模型基于 `../migrations/*.sql` 中的数据库迁移文件生成，运行 `make sql` 时自动更新。

KMS 相关的模型：
- `keys.go` - 密钥表模型
- `key_versions.go` - 密钥版本表模型
- `policies.go` - 策略表模型
- `audit_logs.go` - 审计日志表模型
- `secrets.go` - Secret 表模型

### `/internal/types`

> **自动生成** [go-swagger](https://github.com/go-swagger/go-swagger) 类型和验证。**不要**在此目录放置自己的文件。

这些类型基于 Swagger OpenAPI 规范 `../api/**/*.yml` 生成，运行 `make swagger` 时自动更新。

KMS 相关的类型：
- `/internal/types/kms/` - KMS API 路由参数
- `/internal/types/post_*.go` - API 请求/响应类型

### `/internal/util`

工具函数：

- `/internal/util/http.go` - HTTP 工具函数
- `/internal/util/db/` - 数据库工具函数
- `/internal/util/hashing/` - 哈希工具函数

### `/internal/test`

测试相关代码：

- `/internal/test/test_database.go` - 测试数据库设置
- `/internal/test/test_server.go` - 测试服务器设置
- `/internal/test/fixtures/` - 测试数据

## 开发规范

### 代码组织

- **分层架构**：严格遵循 API → Service → Model → Persistence 的分层架构
- **依赖注入**：使用 Wire 进行依赖注入，所有服务通过 Provider 函数创建
- **接口抽象**：使用接口定义服务契约，便于测试和扩展

### 错误处理

- **错误包装**：使用 `errors.Wrap` 添加上下文信息
- **错误类型**：定义明确的错误变量（如 `ErrKeyNotFound`）
- **错误传播**：Service 层返回错误，Handler 层转换为 HTTP 错误

### 日志记录

- **结构化日志**：使用 `zerolog` 进行结构化日志记录
- **日志级别**：Debug、Info、Warn、Error
- **敏感信息**：不在日志中记录密钥材料、私钥等敏感信息

### 安全规范

- **密钥安全**：密钥在 HSM 内生成和存储，永不离开 HSM
- **参数化查询**：使用参数化查询防止 SQL 注入
- **权限验证**：所有操作都需要通过策略引擎验证权限
- **审计日志**：所有密钥操作都记录审计日志

## 相关文档

- [KMS 开发计划](../docs/KMS开发计划.md)
- [KMS API 使用示例](../docs/KMS-API-使用示例.md)
- [Secret 存储服务实现计划](../docs/Secret存储服务实现计划.md)
- [项目 README](../README.md)

## 参考资源

- [go-starter 文档](https://github.com/allaboutapps/go-starter)
- [Wire 依赖注入](https://github.com/google/wire)
- [SQLBoiler 文档](https://github.com/volatiletech/sqlboiler)
- [HashiCorp Vault 文档](https://www.vaultproject.io/docs)
- [AWS KMS 开发者指南](https://docs.aws.amazon.com/kms/)
- [PKCS#11 标准](https://en.wikipedia.org/wiki/PKCS_11)
