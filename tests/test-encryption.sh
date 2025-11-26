#!/bin/bash
# KMS API 加密解密测试脚本
# 测试数据加密、解密和数据密钥生成功能

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
    echo "$json" | grep -o "\"$key\"[[:space:]]*:[[:space:]]*\"[^\"]*\"" | cut -d'"' -f4
}

# 主测试流程
main() {
    log_info "=== KMS API 加密解密测试 ==="
    log_info "Base URL: $BASE_URL"
    log_info "AES Key ID: ${AES_KEY_ID:-未设置}"
    echo ""
    
    if [ -z "$AES_KEY_ID" ]; then
        log_error "AES_KEY_ID 未设置，无法进行加密测试"
        exit 1
    fi
    
    # 3.1 加密数据
    log_info "Phase 3.1: 加密数据"
    PLAINTEXT="Hello, KMS!"
    PLAINTEXT_B64=$(echo -n "$PLAINTEXT" | base64)
    
    ENCRYPT_DATA="{
        \"key_id\": \"$AES_KEY_ID\",
        \"plaintext\": \"$PLAINTEXT_B64\",
        \"encryption_context\": {
            \"purpose\": \"test\",
            \"environment\": \"development\"
        }
    }"
    
    encrypt_response=$(test_request "加密数据" "POST" "$BASE_URL/api/v1/kms/encrypt" "$ENCRYPT_DATA" "200")
    
    if [ $? -eq 0 ]; then
        CIPHERTEXT=$(extract_json_value "$encrypt_response" "ciphertext_blob")
        if [ -n "$CIPHERTEXT" ]; then
            echo "$CIPHERTEXT" > /tmp/kms_test_ciphertext.txt
            log_info "密文已保存到 /tmp/kms_test_ciphertext.txt"
        fi
    fi
    echo ""
    
    # 3.2 解密数据
    if [ -n "$CIPHERTEXT" ]; then
        log_info "Phase 3.2: 解密数据"
        DECRYPT_DATA="{
            \"ciphertext_blob\": \"$CIPHERTEXT\",
            \"encryption_context\": {
                \"purpose\": \"test\",
                \"environment\": \"development\"
            }
        }"
        
        decrypt_response=$(test_request "解密数据" "POST" "$BASE_URL/api/v1/kms/decrypt" "$DECRYPT_DATA" "200")
        
        if [ $? -eq 0 ]; then
            DECRYPTED_PLAINTEXT_B64=$(extract_json_value "$decrypt_response" "plaintext")
            if [ -n "$DECRYPTED_PLAINTEXT_B64" ]; then
                DECRYPTED_PLAINTEXT=$(echo "$DECRYPTED_PLAINTEXT_B64" | base64 -d)
                log_info "解密后的明文: $DECRYPTED_PLAINTEXT"
                if [ "$DECRYPTED_PLAINTEXT" = "$PLAINTEXT" ]; then
                    log_info "✓ 解密结果与原始明文匹配"
                else
                    log_error "✗ 解密结果与原始明文不匹配"
                fi
            fi
        fi
        echo ""
    fi
    
    # 3.3 生成数据密钥（信封加密）
    log_info "Phase 3.3: 生成数据密钥（信封加密）"
    GENERATE_DATA_KEY_DATA="{
        \"key_id\": \"$AES_KEY_ID\",
        \"number_of_bytes\": 32
    }"
    
    generate_response=$(test_request "生成数据密钥" "POST" "$BASE_URL/api/v1/kms/generate-data-key" "$GENERATE_DATA_KEY_DATA" "200")
    
    if [ $? -eq 0 ]; then
        DATA_KEY_PLAINTEXT=$(extract_json_value "$generate_response" "plaintext")
        DATA_KEY_CIPHERTEXT=$(extract_json_value "$generate_response" "ciphertext_blob")
        if [ -n "$DATA_KEY_PLAINTEXT" ] && [ -n "$DATA_KEY_CIPHERTEXT" ]; then
            log_info "✓ 数据密钥生成成功"
            log_verbose "Plaintext (base64): $DATA_KEY_PLAINTEXT"
            log_verbose "Ciphertext (base64): $DATA_KEY_CIPHERTEXT"
        fi
    fi
    echo ""
    
    # 测试总结
    echo ""
    log_info "=== 测试总结 ==="
    echo -e "${GREEN}通过: $PASSED${NC}"
    echo -e "${RED}失败: $FAILED${NC}"
    
    if [ $FAILED -eq 0 ]; then
        log_info "所有加密解密测试通过！"
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

