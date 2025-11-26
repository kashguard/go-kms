# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Ed25519 密钥支持**: 完整实现了 Ed25519 椭圆曲线密钥的生成、签名和验证功能
  - 编译了支持 Ed25519 的 OpenSSL 3.2.2
  - 编译了启用 EdDSA 的 SoftHSM 2.6.1
  - 使用 `CKM_EC_EDWARDS_KEY_PAIR_GEN` 机制生成 Ed25519 密钥对
  - 使用 `CKM_EDDSA` (0x1057) 机制进行 Ed25519 签名和验证
  - 自动检测并使用自定义编译的 SoftHSM 库（`/home/development/softhsm-ed25519/lib/softhsm/libsofthsm2.so`）

- **PKCS#11 签名验证实现**: 完整实现了基于 PKCS#11 的签名验证流程
  - 实现了通过 `CKA_ID` 属性查找公钥的逻辑
  - 支持 ECDSA (secp256k1, P-256) 和 Ed25519 的签名验证
  - 正确处理 PKCS#11 会话状态，避免 `CKR_OPERATION_ACTIVE` 错误
  - 支持无效签名的正确识别（返回 `valid: false` 而不是错误）

- **SoftHSM 自动初始化增强**:
  - 更新了 `scripts/init-softhsm.sh`，优先使用自定义编译的 SoftHSM
  - 添加了 `/home/development/softhsm-ed25519/lib/softhsm/libsofthsm2.so` 到搜索路径
  - 自动检测并保存 HSM 库路径到 `/tmp/kms_hsm_library`

- **Docker 环境配置**:
  - 在 `docker-compose.yml` 中添加了 `LD_LIBRARY_PATH` 环境变量
  - 配置了持久化的 SoftHSM 数据卷（`~/.config/softhsm2/tokens`）
  - 添加了 OpenSSL 库的自动复制逻辑

### Fixed
- **ECDSA 签名机制**: 修复了 ECDSA 签名使用错误的 PKCS#11 机制问题
  - 将 `CKM_ECDSA_SHA256` 等组合机制改为通用的 `CKM_ECDSA` 机制
  - 摘要计算已在服务层完成，HSM 层只负责签名操作
  - 解决了 `CKR_MECHANISM_INVALID` (0x70) 错误

- **Ed25519 密钥生成**: 修复了密钥生成模板问题
  - 添加了必需的 `CKA_EC_PARAMS` 属性（Ed25519 OID: 1.3.101.112）
  - 添加了 `CKA_LABEL` 和 `CKA_ID` 属性用于对象标识
  - 解决了 `CKR_TEMPLATE_INCOMPLETE` (0xD0) 和 `CKR_ATTRIBUTE_READ_ONLY` (0x10) 错误

- **PKCS#11 会话管理**: 修复了签名验证时的会话状态问题
  - 在查找公钥后立即调用 `FindObjectsFinal` 释放会话
  - 避免了 `CKR_OPERATION_ACTIVE` (0x90) 错误

### Changed
- **构建脚本优化**: 改进了 `scripts/build-softhsm-ed25519.sh`
  - 修改 OpenSSL 和 SoftHSM 安装路径为用户可写目录（`$HOME/openssl-ed25519`, `$HOME/softhsm-ed25519`）
  - 添加了 `RPATH` 配置，确保 SoftHSM 正确链接自定义 OpenSSL
  - 为 SoftHSM 编译添加了 `--enable-eddsa` 标志
  - 添加了自动安装构建依赖（autotools）的逻辑
  - 修复了 ARM64 架构的 OpenSSL 编译目标（`linux-aarch64`）

### Technical Details

#### 支持的密钥类型
- ✅ **AES_256**: 对称加密密钥（加密/解密）
- ✅ **ECC_SECP256K1**: secp256k1 椭圆曲线密钥（签名/验证）
- ✅ **ECC_P256**: NIST P-256 椭圆曲线密钥（签名/验证）
- ✅ **ED25519**: Ed25519 椭圆曲线密钥（签名/验证）- **新增**

#### PKCS#11 机制映射
- **Ed25519 密钥生成**: `CKM_EC_EDWARDS_KEY_PAIR_GEN` (0x1055) + `CKK_EC_EDWARDS` (0x40)
- **Ed25519 签名/验证**: `CKM_EDDSA` (0x1057)
- **ECDSA 签名/验证**: `CKM_ECDSA` (0x1041) - 摘要在服务层计算
- **AES 加密/解密**: `CKM_AES_GCM` (0x1087)

#### 依赖版本
- **OpenSSL**: 3.2.2 (自定义编译，支持 Ed25519)
- **SoftHSM**: 2.6.1 (自定义编译，启用 EdDSA)
- **PKCS#11 Go 绑定**: miekg/pkcs11

### Testing
所有密钥类型和功能已通过完整测试：
- ✅ AES_256 加密/解密
- ✅ ECC_SECP256K1 签名/验证
- ✅ ECC_P256 签名/验证
- ✅ ED25519 签名/验证
- ✅ 无效签名正确拒绝
- ✅ 不同消息签名验证失败

### Migration Notes
- 如果从旧版本升级，需要重新构建 Docker 镜像以包含自定义编译的 OpenSSL 和 SoftHSM
- 执行 `docker compose build` 和 `docker compose up -d` 重新部署
- SoftHSM 数据已持久化到主机的 `~/.config/softhsm2/tokens` 目录

---

## [0.1.0] - Initial Release

### Added
- 基础 KMS 框架
- 密钥管理 API（创建、查询、更新、删除、启用、禁用、轮换）
- 加密/解密服务（AES-256-GCM）
- 签名服务（ECDSA）
- 策略引擎
- 审计日志
- Secret 存储服务
- PostgreSQL 元数据存储
- SoftHSM 集成
- Docker 容器化部署

