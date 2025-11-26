# KMS Crypto 优先开发计划

## 项目目标

开发一个企业级 KMS（密钥管理服务）系统，优先支持 crypto 行业所需的加密功能：

- 密钥生命周期管理（创建、查询、更新、删除、轮换）
- 非对称密钥签名/验证（ECC secp256k1、P-256、Ed25519）
- 对称密钥加密/解密（AES-256）
- SoftHSM 集成（PKCS#11 接口）
- 策略引擎（基础权限控制）
- 审计日志（操作记录）

**重要原则**：

- KMS 只提供密钥管理和基础加密服务，不实现业务逻辑
- 先集成 SoftHSM，设计 HSM 适配器接口便于后续适配其他 HSM
- 遵循 go-starter 框架规范和 .cursorrules 开发规范

## 技术架构

### 分层架构

```
API Layer (internal/api/handlers/kms/)
  ↓
Service Layer (internal/kms/)
  ├── key/          # 密钥管理
  ├── encryption/   # 加密解密服务
  ├── sign/         # 签名验证服务
  ├── policy/       # 策略引擎
  ├── audit/        # 审计日志
  └── auth/         # 认证授权（复用现有）
  ↓
Model Layer (internal/models/) - SQLBoiler 生成
  ↓
Persistence Layer
  ├── Metadata Store (PostgreSQL)
  └── HSM Adapter (PKCS#11 Interface)
      ├── software/  # SoftHSM 实现
      └── pkcs11/   # 通用 PKCS#11 接口
```

## 开发阶段

### Phase 1: 基础设施搭建（Week 1-2）

#### 1.1 数据库设计 ✅

- [x] 创建数据库迁移文件 `migrations/20251126105136-create-kms-tables.sql`
  - `keys` 表：密钥元数据
  - `key_versions` 表：密钥版本管理
  - `policies` 表：策略定义
  - `audit_logs` 表：审计日志
- [x] 运行 `make sql` 生成 SQLBoiler 模型

#### 1.2 HSM 适配器接口设计 ✅

- [x] 创建 `internal/kms/hsm/adapter.go` 定义 HSMAdapter 接口
- [x] 创建 `internal/kms/hsm/types.go` 定义类型

#### 1.3 SoftHSM 集成 ✅

- [x] 创建 `internal/kms/hsm/software/adapter.go` 实现 SoftHSM 适配器
- [x] 使用 `github.com/miekg/pkcs11` 库实现 PKCS#11 接口
- [x] 实现密钥生成、加密、解密、签名、验证功能
- [ ] 添加 SoftHSM 初始化脚本和配置

#### 1.4 存储抽象层 ✅

- [x] 创建 `internal/kms/storage/interface.go` 定义 MetadataStore 接口
- [x] 创建 `internal/kms/storage/postgresql.go` 实现 PostgreSQL 存储
- [x] 实现密钥元数据的 CRUD 操作

### Phase 2: 核心服务实现（Week 3-5）

#### 2.1 密钥管理服务 ✅

- [x] 创建 `internal/kms/key/service.go` 实现 KeyService
- [x] 创建 `internal/kms/key/types.go` 定义类型
- [x] 实现密钥创建（支持 ECC secp256k1、P-256、Ed25519、AES-256）
- [x] 实现密钥查询、更新、删除
- [x] 实现密钥状态管理（Enabled、Disabled、PendingDeletion）
- [x] 实现密钥轮换（创建新版本，保留旧版本）

#### 2.2 加密解密服务 ✅

- [x] 创建 `internal/kms/encryption/service.go` 实现 EncryptionService
- [x] 创建 `internal/kms/encryption/types.go` 定义类型
- [x] 实现对称密钥加密/解密（AES-256）
- [x] 实现数据密钥生成（信封加密）
- [x] 实现加密上下文验证

#### 2.3 签名验证服务 ✅

- [x] 创建 `internal/kms/sign/service.go` 实现 SignService
- [x] 创建 `internal/kms/sign/types.go` 定义类型
- [x] 实现非对称密钥签名（ECC secp256k1、P-256、Ed25519）
- [x] 支持 RAW 和 DIGEST 两种签名模式
- [x] 实现签名验证功能（部分实现，需要公钥查找）

#### 2.4 策略引擎（基础版） ✅

- [x] 创建 `internal/kms/policy/engine.go` 实现 PolicyEngine
- [x] 创建 `internal/kms/policy/types.go` 定义类型
- [x] 实现策略解析和评估
- [x] 支持基础的 Allow/Deny 策略
- [x] 支持密钥级别的权限控制

#### 2.5 审计日志 ✅

- [x] 创建 `internal/kms/audit/logger.go` 实现 AuditLogger
- [x] 创建 `internal/kms/audit/types.go` 定义类型
- [x] 记录所有密钥操作（创建、使用、删除等）
- [x] 记录访问尝试（成功和失败）
- [ ] 实现日志查询和导出功能

### Phase 3: API 层实现（Week 6-7）

#### 3.1 API 定义（Swagger-First）✅

- [x] 在 `api/definitions/kms.yml` 中定义所有 API 类型
  - [x] 密钥管理 API（创建、查询、更新、删除、轮换）
  - [x] 加密解密 API（encrypt、decrypt、generate-data-key）
  - [x] 签名验证 API（sign、verify）
  - [ ] 策略管理 API（create、get、update、delete）- 暂缓
  - [ ] 审计日志 API（query、export）- 暂缓
- [x] 在 `api/paths/kms.yml` 中定义 API 路径
- [x] 在 `api/config/main.yml` 中添加引用（自动包含）
- [x] 运行 `make swagger` 生成 Go 类型

#### 3.2 API Handlers 实现 ✅

- [x] 创建 `internal/api/handlers/kms/keys/` 目录和 handlers
  - [x] `post_create_key.go` - POST /v1/keys
  - [x] `get_key.go` - GET /v1/keys/{key_id}
  - [x] `put_update_key.go` - PUT /v1/keys/{key_id}
  - [x] `delete_key.go` - DELETE /v1/keys/{key_id}
  - [x] `post_enable_key.go` - POST /v1/keys/{key_id}/enable
  - [x] `post_disable_key.go` - POST /v1/keys/{key_id}/disable
  - [x] `post_rotate_key.go` - POST /v1/keys/{key_id}/rotate
  - [x] `get_list_keys.go` - GET /v1/keys
- [x] 创建 `internal/api/handlers/kms/encryption/` 目录和 handlers
  - [x] `post_encrypt.go` - POST /v1/encrypt
  - [x] `post_decrypt.go` - POST /v1/decrypt
  - [x] `post_generate_data_key.go` - POST /v1/generate-data-key
- [x] 创建 `internal/api/handlers/kms/sign/` 目录和 handlers
  - [x] `post_sign.go` - POST /v1/sign
  - [x] `post_verify.go` - POST /v1/verify
- [ ] 创建 `internal/api/handlers/kms/policies/` 目录和 handlers - 暂缓
- [ ] 创建 `internal/api/handlers/kms/audit/` 目录和 handlers - 暂缓

#### 3.3 Wire 依赖注入 ✅

- [x] 在 `internal/api/wire.go` 中添加 KMS 服务 Provider
- [x] 在 `internal/api/server.go` 中添加 KMS 服务字段
- [x] 运行 `make wire` 生成依赖注入代码

#### 3.4 路由注册 ✅

- [x] 在 `internal/api/router/router.go` 中添加 KMS 路由组
- [x] 在 `internal/api/handlers/handlers.go` 中注册所有 KMS 路由

### Phase 4: 配置和集成（Week 8）

#### 4.1 配置管理 ✅

- [x] 在 `internal/config/server_config.go` 中添加 KMS 配置
  ```go
  type KMS struct {
      StorageBackend string  // postgresql
      HSMType        string  // software (SoftHSM)
      HSMLibrary     string  // SoftHSM 库路径
      HSMSlot        int     // HSM Slot
      HSMPIN         string  // HSM PIN
      EnableAudit    bool    // 默认 true
      EnablePolicy   bool    // 默认 true
  }
  ```
- [x] 添加环境变量支持

#### 4.2 服务初始化 ✅

- [x] 在 `cmd/server/server.go` 中初始化 KMS 服务（通过 Wire 自动完成）
- [x] 初始化 SoftHSM（如果配置启用）
- [x] 初始化存储后端（PostgreSQL）
- [x] 初始化策略引擎和审计日志

#### 4.3 测试和文档

- [x] 编写单元测试（核心服务）
  - [x] 策略引擎测试（policy/engine_test.go）
  - [x] 审计日志测试（audit/logger_test.go）
- [ ] 编写集成测试（API 层）
- [x] 更新 README 文档
- [x] 编写 API 使用示例（docs/KMS-API-使用示例.md）

## 关键技术决策

### HSM 适配器设计

- **接口抽象**：定义 `HSMAdapter` 接口，所有 HSM 实现都遵循此接口
- **SoftHSM 实现**：使用 `github.com/miekg/pkcs11` 实现 PKCS#11 标准接口
- **后续扩展**：其他 HSM（硬件 HSM、CloudHSM）只需实现相同接口即可

### 密钥类型支持

- **Phase 1 支持**：
  - ECC secp256k1（Bitcoin/Ethereum）
  - ECC P-256（通用标准）
  - Ed25519（现代、高性能）
  - AES-256（对称加密）
- **后续扩展**：ECC P-384/P-521、RSA-2048/4096

### 签名模式

- **RAW 模式**：直接对原始数据进行签名（业务层处理格式）
- **DIGEST 模式**：对消息摘要进行签名（KMS 处理哈希）

## 文件结构

```
internal/kms/
├── key/
│   ├── service.go          # KeyService 主服务
│   ├── manager.go          # 密钥生命周期管理
│   ├── rotation.go         # 密钥轮换
│   └── types.go            # 类型定义
├── encryption/
│   ├── service.go          # EncryptionService
│   ├── encrypt.go          # 数据加密
│   ├── decrypt.go          # 数据解密
│   ├── datakey.go          # 数据密钥生成
│   └── types.go
├── sign/
│   ├── service.go          # SignService
│   ├── sign.go             # 数字签名
│   ├── verify.go           # 签名验证
│   └── types.go
├── policy/
│   ├── engine.go           # PolicyEngine
│   ├── evaluator.go        # 策略评估
│   ├── parser.go           # 策略解析
│   └── types.go
├── audit/
│   ├── logger.go           # AuditLogger
│   ├── storage.go          # 日志存储
│   └── types.go
├── storage/
│   ├── interface.go        # MetadataStore 接口
│   ├── postgresql.go       # PostgreSQL 实现
│   └── types.go
├── hsm/
│   ├── adapter.go          # HSMAdapter 接口
│   ├── software/
│   │   └── adapter.go      # SoftHSM 实现
│   └── types.go
└── types.go
```

## 依赖库

- `github.com/miekg/pkcs11` - PKCS#11 接口库
- `golang.org/x/crypto` - 加密算法库
- 现有 go-starter 依赖（Wire、SQLBoiler、Echo 等）

## 验收标准

- [x] 可以创建 ECC secp256k1、P-256、Ed25519、AES-256 密钥
- [x] 可以在 SoftHSM 内生成和存储密钥
- [x] 可以对数据进行加密/解密
- [x] 可以对消息进行签名/验证
- [x] 支持密钥轮换和版本管理
- [x] 所有操作记录审计日志
- [ ] API 符合 Swagger 定义
- [ ] 通过单元测试和集成测试

## 当前进度

### 已完成 ✅

1. **数据库设计**：已完成迁移文件和模型生成
2. **HSM 适配器**：接口设计和 SoftHSM 实现已完成
3. **存储层**：PostgreSQL 存储实现已完成（使用 SQLBoiler）
4. **核心服务**：
   - 密钥管理服务 ✅
   - 加密解密服务 ✅
   - 签名验证服务 ✅
   - 策略引擎 ✅
   - 审计日志 ✅

### 进行中 🚧

- 核心服务已编译通过，等待 API 层实现

### 待完成 📋

1. **API 层**：Swagger 定义和 Handlers 实现
2. **Wire 集成**：依赖注入配置
3. **配置管理**：KMS 配置和环境变量
4. **服务初始化**：启动时初始化 KMS 服务
5. **测试**：单元测试和集成测试

## 注意事项

1. **SoftHSM 限制**：
   - Ed25519 支持需要后续改进（当前使用通用密钥类型）
   - 签名验证需要实现公钥查找逻辑

2. **密钥状态**：
   - 默认状态为 "Enabled"，在应用层设置
   - 删除操作设置为 "PendingDeletion"，30 天后永久删除

3. **加密上下文**：
   - 支持可选的加密上下文验证
   - 最大 10 个键值对，键最大 128 字符，值最大 1024 字符

4. **策略引擎**：
   - 当前实现基础版，支持 Allow/Deny
   - 后续可扩展条件验证和资源匹配

## 更新日志

- **2025-11-26**：完成 Phase 1 和 Phase 2 的核心服务实现
  - 数据库迁移和模型生成
  - HSM 适配器和 SoftHSM 集成
  - 存储层实现（PostgreSQL + SQLBoiler）
  - 所有核心服务实现并编译通过

