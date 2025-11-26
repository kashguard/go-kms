# Secret 存储服务实现计划

## 目标

在现有 KMS 系统基础上添加 Secret 存储服务，满足托管钱包客户需求：
- 存储加密的 keystore JSON 数据（500-1000 字节）
- 提供 CreateSecret、GetSecret、UpdateSecret、DeleteSecret、SecretExists 接口
- 支持渐进式迁移和向后兼容
- 复用现有的加密服务、策略引擎和审计日志

## 架构设计

### 数据流
```
客户端数据 → SecretService → EncryptionService (使用全局 KMS 密钥) → 存储到 secrets 表
```

### 核心组件
1. **Secret Service** (`internal/kms/secret/`) - 业务逻辑层
2. **Storage Interface** (`internal/kms/storage/`) - 扩展存储接口
3. **Database Migration** - 新增 secrets 表
4. **API Handlers** (`internal/api/handlers/kms/secrets/`) - REST API
5. **Configuration** - 添加 Secret 相关配置

## 实施步骤

### Phase 1: 数据库和存储层（Week 1）

#### 1.1 数据库迁移
- **文件**: `migrations/YYYYMMDDHHMMSS-create-secrets-table.sql`
- **内容**:
  - 创建 `secrets` 表
    - `key_id` VARCHAR(255) PRIMARY KEY
    - `encrypted_data` BYTEA NOT NULL (加密后的数据)
    - `kms_key_id` VARCHAR(255) NOT NULL (用于加密的 KMS 密钥ID)
    - `key_version` INTEGER NOT NULL (KMS 密钥版本)
    - `created_at` TIMESTAMPTZ
    - `updated_at` TIMESTAMPTZ
  - 创建索引和外键约束
  - 添加 Down 迁移

#### 1.2 扩展存储接口
- **文件**: `internal/kms/storage/interface.go`
- **新增方法**:
  ```go
  SaveSecret(ctx context.Context, secret *Secret) error
  GetSecret(ctx context.Context, keyID string) (*Secret, error)
  UpdateSecret(ctx context.Context, keyID string, secret *Secret) error
  DeleteSecret(ctx context.Context, keyID string) error
  SecretExists(ctx context.Context, keyID string) (bool, error)
  ```

#### 1.3 存储类型定义
- **文件**: `internal/kms/storage/types.go`
- **新增类型**:
  ```go
  type Secret struct {
      KeyID        string
      EncryptedData []byte
      KMSKeyID     string
      KeyVersion   int
      CreatedAt    time.Time
      UpdatedAt    time.Time
  }
  ```

#### 1.4 PostgreSQL 实现
- **文件**: `internal/kms/storage/postgresql.go`
- **实现**: 所有 Secret 相关存储方法
- **使用**: SQLBoiler 模型（运行 `make sql` 生成）

### Phase 2: Secret Service 实现（Week 1-2）

#### 2.1 类型定义
- **文件**: `internal/kms/secret/types.go`
- **定义**:
  - `CreateSecretRequest`
  - `GetSecretResponse`
  - `UpdateSecretRequest`
  - 错误类型

#### 2.2 Service 接口
- **文件**: `internal/kms/secret/service.go`
- **接口**:
  ```go
  type Service interface {
      CreateSecret(ctx context.Context, keyID string, data []byte) (string, error)
      GetSecret(ctx context.Context, keyID string) ([]byte, error)
      UpdateSecret(ctx context.Context, keyID string, data []byte) error
      DeleteSecret(ctx context.Context, keyID string) error
      SecretExists(ctx context.Context, keyID string) (bool, error)
  }
  ```

#### 2.3 Service 实现
- **依赖**:
  - `encryption.Service` - 用于加密/解密
  - `key.Service` - 获取全局 KMS 密钥
  - `storage.MetadataStore` - 存储 Secret
  - `policy.Engine` - 权限控制
  - `audit.Logger` - 审计日志
- **逻辑**:
  - `CreateSecret`: 使用全局 KMS 密钥加密数据，保存到数据库
  - `GetSecret`: 从数据库读取，使用 KMS 密钥解密
  - `UpdateSecret`: 重新加密并更新
  - `DeleteSecret`: 删除记录
  - `SecretExists`: 检查是否存在

#### 2.4 全局 KMS 密钥管理
- **配置**: 在 `internal/config/server_config.go` 中添加 `SecretKMSKeyID`
- **初始化**: 启动时检查/创建全局密钥（如果不存在）
- **密钥类型**: AES-256（对称加密）

### Phase 3: API 层实现（Week 2）

#### 3.1 Swagger API 定义
- **文件**: `api/definitions/kms.yml`
- **新增类型**:
  - `PostCreateSecretPayload`
  - `CreateSecretResponse`
  - `GetSecretResponse`
  - `PutUpdateSecretPayload`
  - `PostDeleteSecretResponse`

#### 3.2 API 路径定义
- **文件**: `api/paths/kms.yml`
- **新增路径**:
  - `POST /api/v1/kms/secrets` - 创建 Secret
  - `GET /api/v1/kms/secrets/{keyId}` - 获取 Secret
  - `PUT /api/v1/kms/secrets/{keyId}` - 更新 Secret
  - `DELETE /api/v1/kms/secrets/{keyId}` - 删除 Secret
  - `HEAD /api/v1/kms/secrets/{keyId}` - 检查 Secret 是否存在

#### 3.3 API Handlers
- **目录**: `internal/api/handlers/kms/secrets/`
- **文件**:
  - `post_create_secret.go`
  - `get_secret.go`
  - `put_update_secret.go`
  - `delete_secret.go`
  - `head_secret_exists.go`

#### 3.4 路由注册
- **文件**: `internal/api/handlers/handlers.go`
- **添加**: 所有 Secret 路由

### Phase 4: 配置和集成（Week 2）

#### 4.1 配置扩展
- **文件**: `internal/config/server_config.go`
- **新增字段**:
  ```go
  type KMS struct {
      // ... 现有字段
      SecretKMSKeyID string // 用于加密 Secret 的全局 KMS 密钥ID
      SecretKMSKeyAlias string // 密钥别名（可选）
  }
  ```
- **环境变量**: `KMS_SECRET_KEY_ID`, `KMS_SECRET_KEY_ALIAS`

#### 4.2 Wire 依赖注入
- **文件**: `internal/api/providers.go`
- **新增**: `NewSecretService` provider
- **文件**: `internal/api/wire.go`
- **添加**: `NewSecretService` 到 `kmsServiceSet`
- **文件**: `internal/api/server.go`
- **添加**: `SecretService` 字段

#### 4.3 服务初始化
- **文件**: `cmd/server/server.go` 或初始化逻辑
- **逻辑**: 启动时检查/创建全局 Secret KMS 密钥

### Phase 5: 渐进式迁移支持（Week 2-3）

#### 5.1 配置开关
- **文件**: `internal/config/server_config.go`
- **新增**: `EnableSecretService bool` (默认 false)
- **环境变量**: `KMS_ENABLE_SECRET_SERVICE`

#### 5.2 兼容性层（可选）
- **文件**: `internal/kms/secret/compat.go`
- **功能**: 支持从旧数据库格式读取（如果需要）

### Phase 6: 测试和文档（Week 3）

#### 6.1 单元测试
- **文件**: `internal/kms/secret/service_test.go`
- **测试**:
  - CreateSecret/GetSecret 流程
  - UpdateSecret
  - DeleteSecret
  - SecretExists
  - 错误场景（密钥不存在、权限 denied 等）

#### 6.2 存储层测试
- **文件**: `internal/kms/storage/postgresql_secret_test.go`
- **测试**: Secret 存储的 CRUD 操作

#### 6.3 集成测试
- **文件**: `internal/api/handlers/kms/secrets/*_test.go`
- **测试**: API 端到端流程

#### 6.4 文档
- **文件**: `docs/KMS-Secret-API-使用示例.md`
- **内容**: API 使用示例、迁移指南

## 关键技术决策

### 1. 全局 KMS 密钥 vs 每个 Secret 独立密钥
- **选择**: 全局 KMS 密钥
- **理由**: 
  - 性能更好（无需为每个 Secret 创建密钥）
  - 适合单一 keystore 场景
  - 简化权限管理

### 2. 加密方式
- **使用**: 现有的 `EncryptionService.Encrypt/Decrypt`
- **密钥类型**: AES-256
- **存储**: 加密后的数据存储在 `secrets.encrypted_data` (BYTEA)

### 3. 错误处理
- **复用**: 现有的错误类型
- **新增**: `ErrSecretNotFound`, `ErrSecretAlreadyExists`

### 4. 审计日志
- **复用**: 现有的 `AuditLogger`
- **记录**: 所有 Secret 操作（创建、读取、更新、删除）

## 文件清单

### 新增文件
- `migrations/YYYYMMDDHHMMSS-create-secrets-table.sql`
- `internal/kms/secret/types.go`
- `internal/kms/secret/service.go`
- `internal/kms/secret/service_test.go`
- `internal/api/handlers/kms/secrets/post_create_secret.go`
- `internal/api/handlers/kms/secrets/get_secret.go`
- `internal/api/handlers/kms/secrets/put_update_secret.go`
- `internal/api/handlers/kms/secrets/delete_secret.go`
- `internal/api/handlers/kms/secrets/head_secret_exists.go`
- `docs/KMS-Secret-API-使用示例.md`

### 修改文件
- `internal/kms/storage/interface.go` - 添加 Secret 方法
- `internal/kms/storage/types.go` - 添加 Secret 类型
- `internal/kms/storage/postgresql.go` - 实现 Secret 存储
- `internal/config/server_config.go` - 添加 Secret 配置
- `internal/api/providers.go` - 添加 SecretService provider
- `internal/api/wire.go` - 注册 SecretService
- `internal/api/server.go` - 添加 SecretService 字段
- `internal/api/handlers/handlers.go` - 注册 Secret 路由
- `api/definitions/kms.yml` - 添加 Secret API 定义
- `api/paths/kms.yml` - 添加 Secret API 路径

## 验收标准

- [ ] 可以创建 Secret 并存储加密数据
- [ ] 可以获取并解密 Secret 数据
- [ ] 可以更新已存在的 Secret
- [ ] 可以删除 Secret
- [ ] 可以检查 Secret 是否存在
- [ ] 所有操作记录审计日志
- [ ] 支持策略权限控制
- [ ] API 符合 Swagger 定义
- [ ] 通过单元测试和集成测试
- [ ] 性能满足要求（GetSecret < 100ms P99）

## 风险与缓解

### 风险 1: 全局密钥单点故障
- **缓解**: 支持密钥轮换，使用密钥版本管理

### 风险 2: 性能问题
- **缓解**: 
  - 使用数据库索引优化查询
  - 考虑添加缓存层（可选，需注意安全）

### 风险 3: 数据迁移复杂性
- **缓解**: 
  - 提供详细的迁移脚本
  - 支持渐进式迁移（配置开关）

