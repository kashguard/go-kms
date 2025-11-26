#!/bin/bash
# KMS API 审计日志测试脚本
# 测试审计日志查询功能

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

# 主测试流程
main() {
    log_info "=== KMS API 审计日志测试 ==="
    log_info "Base URL: $BASE_URL"
    echo ""
    
    # 6.1 查询审计日志
    log_info "Phase 6.1: 查询审计日志"
    test_request "查询审计日志" "GET" "$BASE_URL/api/v1/kms/audit-logs?limit=10" "" "200"
    echo ""
    
    # 6.2 按时间范围查询
    log_info "Phase 6.2: 按时间范围查询"
    TODAY=$(date -u +"%Y-%m-%dT00:00:00Z")
    TOMORROW=$(date -u -v+1d +"%Y-%m-%dT23:59:59Z" 2>/dev/null || date -u -d "+1 day" +"%Y-%m-%dT23:59:59Z" 2>/dev/null || date -u +"%Y-%m-%dT23:59:59Z")
    
    test_request "按时间范围查询" "GET" "$BASE_URL/api/v1/kms/audit-logs?start_time=$TODAY&end_time=$TOMORROW" "" "200"
    echo ""
    
    # 6.3 按密钥ID查询
    if [ -n "$AES_KEY_ID" ]; then
        log_info "Phase 6.3: 按密钥ID查询"
        test_request "按密钥ID查询" "GET" "$BASE_URL/api/v1/kms/audit-logs?key_id=$AES_KEY_ID" "" "200"
        echo ""
    else
        log_warn "AES_KEY_ID 未设置，跳过按密钥ID查询测试"
    fi
    
    # 测试总结
    echo ""
    log_info "=== 测试总结 ==="
    echo -e "${GREEN}通过: $PASSED${NC}"
    echo -e "${RED}失败: $FAILED${NC}"
    
    if [ $FAILED -eq 0 ]; then
        log_info "所有审计日志测试通过！"
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

