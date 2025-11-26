#!/bin/bash
# KMS API 密钥管理测试脚本
# 测试密钥的创建、查询、更新、启用/禁用、轮换等功能

set -e

# 配置
BASE_URL="${BASE_URL:-http://localhost:8080}"
VERBOSE="${VERBOSE:-false}"
TOKEN_FILE="${TOKEN_FILE:-/tmp/kms_test_token.txt}"
KEY_IDS_FILE="${KEY_IDS_FILE:-/tmp/kms_test_key_ids.txt}"

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# 测试计数器
PASSED=0
FAILED=0

# 加载 token
if [ -f "$TOKEN_FILE" ]; then
    TOKEN=$(cat "$TOKEN_FILE")
    export TOKEN
else
    echo -e "${RED}[ERROR]${NC} Token 文件不存在: $TOKEN_FILE"
    echo "请先运行 test-auth.sh 获取 token"
    exit 1
fi

# 辅助函数
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_verbose() {
    if [ "$VERBOSE" = "true" ]; then
        echo -e "[VERBOSE] $1"
    fi
}

# 测试函数
test_request() {
    local test_name="$1"
    local method="$2"
    local url="$3"
    local data="$4"
    local expected_status="$5"
    
    log_info "Testing: $test_name"
    
    local start_time=$(date +%s%N)
    local response
    local status_code
    
    if [ -n "$data" ]; then
        response=$(curl -s -w "\n%{http_code}" -X "$method" "$url" \
            -H 'Content-Type: application/json' \
            -H "Authorization: Bearer $TOKEN" \
            -d "$data" 2>&1)
    else
        response=$(curl -s -w "\n%{http_code}" -X "$method" "$url" \
            -H 'Content-Type: application/json' \
            -H "Authorization: Bearer $TOKEN" 2>&1)
    fi
    
    local end_time=$(date +%s%N)
    local duration=$(( (end_time - start_time) / 1000000 ))
    
    status_code=$(echo "$response" | tail -n1)
    body=$(echo "$response" | sed '$d')
    
    log_verbose "Status Code: $status_code"
    log_verbose "Response: $body"
    log_verbose "Duration: ${duration}ms"
    
    if [ "$status_code" = "$expected_status" ]; then
        echo -e "${GREEN}✓ PASSED${NC} - $test_name (${duration}ms)"
        ((PASSED++))
        echo "$body"
        return 0
    else
        echo -e "${RED}✗ FAILED${NC} - $test_name"
        echo -e "  Expected: $expected_status, Got: $status_code"
        echo -e "  Response: $body"
        ((FAILED++))
        return 1
    fi
}

# 解析 JSON 响应
extract_json_value() {
    local json="$1"
    local key="$2"
    echo "$json" | grep -o "\"$key\"[[:space:]]*:[[:space:]]*\"[^\"]*\"" | cut -d'"' -f4
}

# 保存 key_id
save_key_id() {
    local key_type="$1"
    local key_id="$2"
    echo "${key_type}=${key_id}" >> "$KEY_IDS_FILE"
    export "${key_type}_KEY_ID"="$key_id"
    log_info "$key_type Key ID: $key_id"
}

# 主测试流程
main() {
    log_info "=== KMS API 密钥管理测试 ==="
    log_info "Base URL: $BASE_URL"
    echo ""
    
    # 清空 key_ids 文件
    > "$KEY_IDS_FILE"
    
    # 2.1 创建密钥 - AES_256
    log_info "Phase 2.1: 创建密钥 - AES_256"
    CREATE_AES_DATA='{
        "key_type": "AES_256",
        "alias": "test-aes-key",
        "description": "Test AES encryption key"
    }'
    
    response=$(test_request "创建 AES_256 密钥" "POST" "$BASE_URL/api/v1/kms/keys" "$CREATE_AES_DATA" "201")
    if [ $? -eq 0 ]; then
        AES_KEY_ID=$(extract_json_value "$response" "key_id")
        if [ -n "$AES_KEY_ID" ]; then
            save_key_id "AES" "$AES_KEY_ID"
        fi
    fi
    echo ""
    
    # 2.2 创建密钥 - ECC_SECP256K1
    log_info "Phase 2.2: 创建密钥 - ECC_SECP256K1"
    CREATE_SECP256K1_DATA='{
        "key_type": "ECC_SECP256K1",
        "alias": "test-secp256k1-key",
        "description": "Test secp256k1 signing key"
    }'
    
    response=$(test_request "创建 ECC_SECP256K1 密钥" "POST" "$BASE_URL/api/v1/kms/keys" "$CREATE_SECP256K1_DATA" "201")
    if [ $? -eq 0 ]; then
        SECP256K1_KEY_ID=$(extract_json_value "$response" "key_id")
        if [ -n "$SECP256K1_KEY_ID" ]; then
            save_key_id "SECP256K1" "$SECP256K1_KEY_ID"
        fi
    fi
    echo ""
    
    # 2.3 创建密钥 - ECC_P256
    log_info "Phase 2.3: 创建密钥 - ECC_P256"
    CREATE_P256_DATA='{
        "key_type": "ECC_P256",
        "alias": "test-p256-key",
        "description": "Test P-256 signing key"
    }'
    
    response=$(test_request "创建 ECC_P256 密钥" "POST" "$BASE_URL/api/v1/kms/keys" "$CREATE_P256_DATA" "201")
    if [ $? -eq 0 ]; then
        P256_KEY_ID=$(extract_json_value "$response" "key_id")
        if [ -n "$P256_KEY_ID" ]; then
            save_key_id "P256" "$P256_KEY_ID"
        fi
    fi
    echo ""
    
    # 2.4 创建密钥 - ED25519
    log_info "Phase 2.4: 创建密钥 - ED25519"
    CREATE_ED25519_DATA='{
        "key_type": "ED25519",
        "alias": "test-ed25519-key",
        "description": "Test Ed25519 signing key"
    }'
    
    response=$(test_request "创建 ED25519 密钥" "POST" "$BASE_URL/api/v1/kms/keys" "$CREATE_ED25519_DATA" "201")
    if [ $? -eq 0 ]; then
        ED25519_KEY_ID=$(extract_json_value "$response" "key_id")
        if [ -n "$ED25519_KEY_ID" ]; then
            save_key_id "ED25519" "$ED25519_KEY_ID"
        fi
    fi
    echo ""
    
    # 2.5 获取密钥详情
    if [ -n "$AES_KEY_ID" ]; then
        log_info "Phase 2.5: 获取密钥详情"
        test_request "获取密钥详情" "GET" "$BASE_URL/api/v1/kms/keys/$AES_KEY_ID" "" "200"
        echo ""
    fi
    
    # 2.6 列出所有密钥
    log_info "Phase 2.6: 列出所有密钥"
    test_request "列出所有密钥" "GET" "$BASE_URL/api/v1/kms/keys" "" "200"
    echo ""
    
    # 2.7 更新密钥
    if [ -n "$AES_KEY_ID" ]; then
        log_info "Phase 2.7: 更新密钥"
        UPDATE_DATA="{
            \"description\": \"Updated description\",
            \"tags\": {
                \"environment\": \"test\",
                \"updated\": \"true\"
            }
        }"
        test_request "更新密钥" "PUT" "$BASE_URL/api/v1/kms/keys/$AES_KEY_ID" "$UPDATE_DATA" "200"
        echo ""
    fi
    
    # 2.8 禁用密钥
    if [ -n "$AES_KEY_ID" ]; then
        log_info "Phase 2.8: 禁用密钥"
        test_request "禁用密钥" "POST" "$BASE_URL/api/v1/kms/keys/$AES_KEY_ID/disable" "" "200"
        echo ""
    fi
    
    # 2.9 启用密钥
    if [ -n "$AES_KEY_ID" ]; then
        log_info "Phase 2.9: 启用密钥"
        test_request "启用密钥" "POST" "$BASE_URL/api/v1/kms/keys/$AES_KEY_ID/enable" "" "200"
        echo ""
    fi
    
    # 2.10 轮换密钥
    if [ -n "$AES_KEY_ID" ]; then
        log_info "Phase 2.10: 轮换密钥"
        test_request "轮换密钥" "POST" "$BASE_URL/api/v1/kms/keys/$AES_KEY_ID/rotate" "" "200"
        echo ""
    fi
    
    # 测试总结
    echo ""
    log_info "=== 测试总结 ==="
    echo -e "${GREEN}通过: $PASSED${NC}"
    echo -e "${RED}失败: $FAILED${NC}"
    log_info "Key IDs 已保存到 $KEY_IDS_FILE"
    
    if [ $FAILED -eq 0 ]; then
        log_info "所有密钥管理测试通过！"
        return 0
    else
        log_error "部分测试失败"
        return 1
    fi
}

# 解析命令行参数
while [[ $# -gt 0 ]]; do
    case $1 in
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        -u|--url)
            BASE_URL="$2"
            shift 2
            ;;
        -h|--help)
            echo "Usage: $0 [OPTIONS]"
            echo "Options:"
            echo "  -v, --verbose   显示详细输出"
            echo "  -u, --url URL   设置 API 基础 URL (默认: http://localhost:8080)"
            echo "  -h, --help      显示帮助信息"
            exit 0
            ;;
        *)
            log_error "未知参数: $1"
            exit 1
            ;;
    esac
done

# 运行测试
main "$@"

