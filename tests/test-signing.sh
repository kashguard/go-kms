#!/bin/bash
# KMS API 签名验证测试脚本
# 测试数字签名和验证功能，支持 RAW 和 DIGEST 模式

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

# 加载 token 和 key_ids
if [ -f "$TOKEN_FILE" ]; then
    TOKEN=$(cat "$TOKEN_FILE")
    export TOKEN
else
    echo -e "${RED}[ERROR]${NC} Token 文件不存在: $TOKEN_FILE"
    echo "请先运行 test-auth.sh 获取 token"
    exit 1
fi

if [ -f "$KEY_IDS_FILE" ]; then
    source "$KEY_IDS_FILE"
else
    echo -e "${RED}[ERROR]${NC} Key IDs 文件不存在: $KEY_IDS_FILE"
    echo "请先运行 test-keys.sh 创建密钥"
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
    # 尝试提取字符串值
    local value=$(echo "$json" | grep -o "\"$key\"[[:space:]]*:[[:space:]]*\"[^\"]*\"" | cut -d'"' -f4)
    if [ -z "$value" ]; then
        # 尝试提取布尔值
        value=$(echo "$json" | grep -o "\"$key\"[[:space:]]*:[[:space:]]*\(true\|false\)" | grep -o "\(true\|false\)")
    fi
    echo "$value"
}

# 主测试流程
main() {
    log_info "=== KMS API 签名验证测试 ==="
    log_info "Base URL: $BASE_URL"
    log_info "SECP256K1 Key ID: ${SECP256K1_KEY_ID:-未设置}"
    log_info "P256 Key ID: ${P256_KEY_ID:-未设置}"
    log_info "ED25519 Key ID: ${ED25519_KEY_ID:-未设置}"
    echo ""
    
    # 4.1 签名数据 - ECC_SECP256K1 (RAW)
    if [ -n "$SECP256K1_KEY_ID" ]; then
        log_info "Phase 4.1: 签名数据 - ECC_SECP256K1 (RAW)"
        MESSAGE="Hello, KMS!"
        MESSAGE_B64=$(echo -n "$MESSAGE" | base64)
        
        SIGN_DATA="{
            \"key_id\": \"$SECP256K1_KEY_ID\",
            \"message\": \"$MESSAGE_B64\",
            \"message_type\": \"RAW\",
            \"algorithm\": \"ECDSA_SHA256\"
        }"
        
        sign_response=$(test_request "签名数据 (ECC_SECP256K1 RAW)" "POST" "$BASE_URL/api/v1/kms/sign" "$SIGN_DATA" "200")
        
        if [ $? -eq 0 ]; then
            SIGNATURE=$(extract_json_value "$sign_response" "signature")
            if [ -n "$SIGNATURE" ]; then
                echo "$SIGNATURE" > /tmp/kms_test_signature_secp256k1.txt
                log_info "签名已保存到 /tmp/kms_test_signature_secp256k1.txt"
            fi
        fi
        echo ""
        
        # 4.2 验证签名 - ECC_SECP256K1
        if [ -n "$SIGNATURE" ]; then
            log_info "Phase 4.2: 验证签名 - ECC_SECP256K1"
            VERIFY_DATA="{
                \"key_id\": \"$SECP256K1_KEY_ID\",
                \"message\": \"$MESSAGE_B64\",
                \"message_type\": \"RAW\",
                \"signature\": \"$SIGNATURE\",
                \"algorithm\": \"ECDSA_SHA256\"
            }"
            
            verify_response=$(test_request "验证签名 (ECC_SECP256K1)" "POST" "$BASE_URL/api/v1/kms/verify" "$VERIFY_DATA" "200")
            
            if [ $? -eq 0 ]; then
                SIGNATURE_VALID=$(extract_json_value "$verify_response" "signature_valid")
                if [ "$SIGNATURE_VALID" = "true" ]; then
                    log_info "✓ 签名验证成功"
                else
                    log_error "✗ 签名验证失败"
                fi
            fi
            echo ""
        fi
    else
        log_warn "SECP256K1_KEY_ID 未设置，跳过 ECC_SECP256K1 测试"
    fi
    
    # 4.3 签名数据 - ED25519 (RAW)
    if [ -n "$ED25519_KEY_ID" ]; then
        log_info "Phase 4.3: 签名数据 - ED25519 (RAW)"
        MESSAGE_ED25519="Test Ed25519"
        MESSAGE_ED25519_B64=$(echo -n "$MESSAGE_ED25519" | base64)
        
        SIGN_ED25519_DATA="{
            \"key_id\": \"$ED25519_KEY_ID\",
            \"message\": \"$MESSAGE_ED25519_B64\",
            \"message_type\": \"RAW\",
            \"algorithm\": \"ED25519\"
        }"
        
        sign_ed25519_response=$(test_request "签名数据 (ED25519 RAW)" "POST" "$BASE_URL/api/v1/kms/sign" "$SIGN_ED25519_DATA" "200")
        
        if [ $? -eq 0 ]; then
            SIGNATURE_ED25519=$(extract_json_value "$sign_ed25519_response" "signature")
            if [ -n "$SIGNATURE_ED25519" ]; then
                log_info "✓ ED25519 签名生成成功"
            fi
        fi
        echo ""
    else
        log_warn "ED25519_KEY_ID 未设置，跳过 ED25519 测试"
    fi
    
    # 4.4 签名数据 - DIGEST 模式
    if [ -n "$P256_KEY_ID" ]; then
        log_info "Phase 4.4: 签名数据 - DIGEST 模式 (ECC_P256)"
        MESSAGE_DIGEST="Hello, KMS!"
        
        # 计算 SHA256 digest
        if command -v sha256sum >/dev/null 2>&1; then
            DIGEST_HEX=$(echo -n "$MESSAGE_DIGEST" | sha256sum | cut -d' ' -f1)
            DIGEST_B64=$(echo "$DIGEST_HEX" | xxd -r -p | base64)
        elif command -v shasum >/dev/null 2>&1; then
            DIGEST_HEX=$(echo -n "$MESSAGE_DIGEST" | shasum -a 256 | cut -d' ' -f1)
            DIGEST_B64=$(echo "$DIGEST_HEX" | xxd -r -p | base64)
        else
            log_error "无法计算 SHA256 digest，需要 sha256sum 或 shasum 命令"
            DIGEST_B64=""
        fi
        
        if [ -n "$DIGEST_B64" ]; then
            SIGN_DIGEST_DATA="{
                \"key_id\": \"$P256_KEY_ID\",
                \"message\": \"$DIGEST_B64\",
                \"message_type\": \"DIGEST\",
                \"algorithm\": \"ECDSA_SHA256\"
            }"
            
            sign_digest_response=$(test_request "签名数据 (DIGEST 模式)" "POST" "$BASE_URL/api/v1/kms/sign" "$SIGN_DIGEST_DATA" "200")
            
            if [ $? -eq 0 ]; then
                SIGNATURE_DIGEST=$(extract_json_value "$sign_digest_response" "signature")
                if [ -n "$SIGNATURE_DIGEST" ]; then
                    log_info "✓ DIGEST 模式签名生成成功"
                fi
            fi
        fi
        echo ""
    else
        log_warn "P256_KEY_ID 未设置，跳过 DIGEST 模式测试"
    fi
    
    # 测试总结
    echo ""
    log_info "=== 测试总结 ==="
    echo -e "${GREEN}通过: $PASSED${NC}"
    echo -e "${RED}失败: $FAILED${NC}"
    
    if [ $FAILED -eq 0 ]; then
        log_info "所有签名验证测试通过！"
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

