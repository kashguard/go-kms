#!/bin/bash
# KMS API 错误场景测试脚本
# 测试各种错误场景，包括未认证访问、无效 token、资源不存在等

set -e

# 配置
BASE_URL="${BASE_URL:-http://localhost:8080}"
VERBOSE="${VERBOSE:-false}"
TOKEN_FILE="${TOKEN_FILE:-/tmp/kms_test_token.txt}"
KEY_IDS_FILE="${KEY_IDS_FILE:-/tmp/kms_test_key_ids.txt}"
CIPHERTEXT_FILE="${CIPHERTEXT_FILE:-/tmp/kms_test_ciphertext.txt}"
SIGNATURE_FILE="${SIGNATURE_FILE:-/tmp/kms_test_signature_secp256k1.txt}"

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# 测试计数器
PASSED=0
FAILED=0

# 加载 token 和 key_ids（可选，某些测试不需要）
if [ -f "$TOKEN_FILE" ]; then
    TOKEN=$(cat "$TOKEN_FILE")
    export TOKEN
fi

if [ -f "$KEY_IDS_FILE" ]; then
    source "$KEY_IDS_FILE"
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
    local auth_header="${6:-Bearer $TOKEN}"
    
    log_info "Testing: $test_name"
    
    local start_time=$(date +%s%N)
    local response
    local status_code
    
    if [ -n "$data" ]; then
        if [ -n "$auth_header" ] && [ "$auth_header" != "none" ]; then
            response=$(curl -s -w "\n%{http_code}" -X "$method" "$url" \
                -H 'Content-Type: application/json' \
                -H "Authorization: $auth_header" \
                -d "$data" 2>&1)
        else
            response=$(curl -s -w "\n%{http_code}" -X "$method" "$url" \
                -H 'Content-Type: application/json' \
                -d "$data" 2>&1)
        fi
    else
        if [ -n "$auth_header" ] && [ "$auth_header" != "none" ]; then
            response=$(curl -s -w "\n%{http_code}" -X "$method" "$url" \
                -H 'Content-Type: application/json' \
                -H "Authorization: $auth_header" 2>&1)
        else
            response=$(curl -s -w "\n%{http_code}" -X "$method" "$url" \
                -H 'Content-Type: application/json' 2>&1)
        fi
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

# 主测试流程
main() {
    log_info "=== KMS API 错误场景测试 ==="
    log_info "Base URL: $BASE_URL"
    echo ""
    
    # 8.1 未认证访问
    log_info "Phase 8.1: 未认证访问"
    test_request "未认证访问" "GET" "$BASE_URL/api/v1/kms/keys" "" "401" "none"
    echo ""
    
    # 8.2 无效 token
    log_info "Phase 8.2: 无效 token"
    test_request "无效 token" "GET" "$BASE_URL/api/v1/kms/keys" "" "401" "Bearer invalid-token-12345"
    echo ""
    
    # 8.3 密钥不存在
    if [ -n "$TOKEN" ]; then
        log_info "Phase 8.3: 密钥不存在"
        test_request "密钥不存在" "GET" "$BASE_URL/api/v1/kms/keys/non-existent-key-12345" "" "404"
        echo ""
    else
        log_warn "TOKEN 未设置，跳过需要认证的测试"
    fi
    
    # 8.4 使用禁用的密钥
    if [ -n "$TOKEN" ] && [ -n "$AES_KEY_ID" ]; then
        log_info "Phase 8.4: 使用禁用的密钥"
        
        # 先禁用密钥
        log_info "  禁用密钥..."
        curl -s -X POST "$BASE_URL/api/v1/kms/keys/$AES_KEY_ID/disable" \
            -H "Authorization: Bearer $TOKEN" > /dev/null
        
        # 尝试加密（应该失败）
        ENCRYPT_DATA="{
            \"key_id\": \"$AES_KEY_ID\",
            \"plaintext\": \"$(echo -n "test" | base64)\"
        }"
        
        test_request "使用禁用的密钥加密" "POST" "$BASE_URL/api/v1/kms/encrypt" "$ENCRYPT_DATA" "400"
        
        # 重新启用密钥
        log_info "  重新启用密钥..."
        curl -s -X POST "$BASE_URL/api/v1/kms/keys/$AES_KEY_ID/enable" \
            -H "Authorization: Bearer $TOKEN" > /dev/null
        echo ""
    else
        log_warn "TOKEN 或 AES_KEY_ID 未设置，跳过禁用密钥测试"
    fi
    
    # 8.5 错误的加密上下文
    if [ -n "$TOKEN" ] && [ -f "$CIPHERTEXT_FILE" ]; then
        log_info "Phase 8.5: 错误的加密上下文"
        CIPHERTEXT=$(cat "$CIPHERTEXT_FILE")
        
        DECRYPT_DATA="{
            \"ciphertext_blob\": \"$CIPHERTEXT\",
            \"encryption_context\": {
                \"purpose\": \"wrong-context\"
            }
        }"
        
        test_request "错误的加密上下文" "POST" "$BASE_URL/api/v1/kms/decrypt" "$DECRYPT_DATA" "400"
        echo ""
    else
        log_warn "TOKEN 或 CIPHERTEXT 未设置，跳过加密上下文测试"
    fi
    
    # 8.6 无效的签名验证
    if [ -n "$TOKEN" ] && [ -n "$SECP256K1_KEY_ID" ] && [ -f "$SIGNATURE_FILE" ]; then
        log_info "Phase 8.6: 无效的签名验证"
        SIGNATURE=$(cat "$SIGNATURE_FILE")
        WRONG_MESSAGE_B64=$(echo -n "Different message" | base64)
        
        VERIFY_DATA="{
            \"key_id\": \"$SECP256K1_KEY_ID\",
            \"message\": \"$WRONG_MESSAGE_B64\",
            \"message_type\": \"RAW\",
            \"signature\": \"$SIGNATURE\",
            \"algorithm\": \"ECDSA_SHA256\"
        }"
        
        verify_response=$(test_request "无效的签名验证" "POST" "$BASE_URL/api/v1/kms/verify" "$VERIFY_DATA" "200")
        
        if [ $? -eq 0 ]; then
            # 检查 signature_valid 是否为 false
            if echo "$verify_response" | grep -q '"signature_valid"[[:space:]]*:[[:space:]]*false'; then
                log_info "✓ 签名验证正确返回 false"
            else
                log_error "✗ 签名验证应该返回 false"
            fi
        fi
        echo ""
    else
        log_warn "TOKEN、SECP256K1_KEY_ID 或 SIGNATURE 未设置，跳过签名验证测试"
    fi
    
    # 8.7 Secret 服务未启用
    if [ -n "$TOKEN" ]; then
        log_info "Phase 8.7: Secret 服务未启用"
        SECRET_DATA="{
            \"key_id\": \"test-secret-1\",
            \"data\": \"$(echo -n "secret data" | base64)\"
        }"
        
        test_request "Secret 服务未启用" "POST" "$BASE_URL/api/v1/kms/secrets" "$SECRET_DATA" "503"
        echo ""
    fi
    
    # 8.8 无效的密钥类型
    if [ -n "$TOKEN" ]; then
        log_info "Phase 8.8: 无效的密钥类型"
        INVALID_KEY_DATA='{
            "key_type": "INVALID_KEY_TYPE",
            "alias": "invalid-key"
        }'
        
        test_request "无效的密钥类型" "POST" "$BASE_URL/api/v1/kms/keys" "$INVALID_KEY_DATA" "400"
        echo ""
    fi
    
    # 8.9 无效的算法
    if [ -n "$TOKEN" ] && [ -n "$AES_KEY_ID" ]; then
        log_info "Phase 8.9: 无效的算法（使用对称密钥签名）"
        SIGN_INVALID_DATA="{
            \"key_id\": \"$AES_KEY_ID\",
            \"message\": \"$(echo -n "test" | base64)\",
            \"message_type\": \"RAW\",
            \"algorithm\": \"ECDSA_SHA256\"
        }"
        
        test_request "无效的算法" "POST" "$BASE_URL/api/v1/kms/sign" "$SIGN_INVALID_DATA" "400"
        echo ""
    fi
    
    # 测试总结
    echo ""
    log_info "=== 测试总结 ==="
    echo -e "${GREEN}通过: $PASSED${NC}"
    echo -e "${RED}失败: $FAILED${NC}"
    
    if [ $FAILED -eq 0 ]; then
        log_info "所有错误场景测试通过！"
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

