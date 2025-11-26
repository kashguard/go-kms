#!/bin/bash
# KMS API 策略管理测试脚本
# 测试策略的创建、查询、更新和删除功能

set -e

# 配置
BASE_URL="${BASE_URL:-http://localhost:8080}"
VERBOSE="${VERBOSE:-false}"
TOKEN_FILE="${TOKEN_FILE:-/tmp/kms_test_token.txt}"

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

# 主测试流程
main() {
    log_info "=== KMS API 策略管理测试 ==="
    log_info "Base URL: $BASE_URL"
    echo ""
    
    POLICY_ID="test-policy-$(date +%s)"
    
    # 5.1 创建策略
    log_info "Phase 5.1: 创建策略"
    CREATE_POLICY_DATA="{
        \"policy_id\": \"$POLICY_ID\",
        \"description\": \"Test policy for KMS keys\",
        \"policy_document\": {
            \"Version\": \"2012-10-17\",
            \"Statement\": [
                {
                    \"Effect\": \"Allow\",
                    \"Action\": [\"create_key\", \"use_key\"],
                    \"Resource\": \"*\"
                }
            ]
        }
    }"
    
    create_response=$(test_request "创建策略" "POST" "$BASE_URL/api/v1/kms/policies" "$CREATE_POLICY_DATA" "201")
    echo ""
    
    # 5.2 获取策略
    log_info "Phase 5.2: 获取策略"
    test_request "获取策略" "GET" "$BASE_URL/api/v1/kms/policies/$POLICY_ID" "" "200"
    echo ""
    
    # 5.3 列出所有策略
    log_info "Phase 5.3: 列出所有策略"
    test_request "列出所有策略" "GET" "$BASE_URL/api/v1/kms/policies" "" "200"
    echo ""
    
    # 5.4 更新策略
    log_info "Phase 5.4: 更新策略"
    UPDATE_POLICY_DATA="{
        \"description\": \"Updated test policy\",
        \"policy_document\": {
            \"Version\": \"2012-10-17\",
            \"Statement\": [
                {
                    \"Effect\": \"Allow\",
                    \"Action\": [\"create_key\", \"use_key\", \"delete_key\"],
                    \"Resource\": \"*\"
                }
            ]
        }
    }"
    
    test_request "更新策略" "PUT" "$BASE_URL/api/v1/kms/policies/$POLICY_ID" "$UPDATE_POLICY_DATA" "200"
    echo ""
    
    # 5.5 删除策略
    log_info "Phase 5.5: 删除策略"
    test_request "删除策略" "DELETE" "$BASE_URL/api/v1/kms/policies/$POLICY_ID" "" "204"
    echo ""
    
    # 验证删除
    log_info "验证策略已删除"
    test_request "验证策略已删除" "GET" "$BASE_URL/api/v1/kms/policies/$POLICY_ID" "" "404"
    echo ""
    
    # 测试总结
    echo ""
    log_info "=== 测试总结 ==="
    echo -e "${GREEN}通过: $PASSED${NC}"
    echo -e "${RED}失败: $FAILED${NC}"
    
    if [ $FAILED -eq 0 ]; then
        log_info "所有策略管理测试通过！"
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

