#!/bin/bash
# KMS API 认证流程测试脚本
# 测试用户注册、登录和 token 刷新功能

set -e

# 配置
BASE_URL="${BASE_URL:-http://localhost:8080}"
VERBOSE="${VERBOSE:-false}"
TOKEN_FILE="${TOKEN_FILE:-/tmp/kms_test_token.txt}"
REFRESH_TOKEN_FILE="${REFRESH_TOKEN_FILE:-/tmp/kms_test_refresh_token.txt}"

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# 测试计数器
PASSED=0
FAILED=0

# 辅助函数
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
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
            -H "Authorization: Bearer ${TOKEN:-}" \
            -d "$data" 2>&1)
    else
        response=$(curl -s -w "\n%{http_code}" -X "$method" "$url" \
            -H 'Content-Type: application/json' \
            -H "Authorization: Bearer ${TOKEN:-}" 2>&1)
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
    log_info "=== KMS API 认证流程测试 ==="
    log_info "Base URL: $BASE_URL"
    echo ""
    
    # 1.1 用户注册
    log_info "Phase 1.1: 用户注册"
    REGISTER_DATA='{
        "username": "testuser@example.com",
        "password": "correct horse battery staple"
    }'
    
    set +e
    register_response=$(test_request "用户注册" "POST" "$BASE_URL/api/v1/auth/register" "$REGISTER_DATA" "201")
    register_status=$?
    set -e
    
    # 检查是否是 409 (用户已存在)，这也是可以接受的
    if [ $register_status -ne 0 ]; then
        status_code=$(echo "$register_response" | tail -n1)
        if [ "$status_code" = "409" ]; then
            log_info "用户已存在 (409)，继续测试"
        else
            log_error "用户注册失败，状态码: $status_code"
            # 继续测试，可能用户已存在
        fi
    else
        log_info "用户注册成功"
    fi
    echo ""
    
    # 1.2 用户登录
    log_info "Phase 1.2: 用户登录"
    LOGIN_DATA='{
        "username": "testuser@example.com",
        "password": "correct horse battery staple"
    }'
    
    login_response=$(test_request "用户登录" "POST" "$BASE_URL/api/v1/auth/login" "$LOGIN_DATA" "200")
    
    if [ $? -eq 0 ]; then
        # 提取 token
        TOKEN=$(extract_json_value "$login_response" "access_token")
        REFRESH_TOKEN=$(extract_json_value "$login_response" "refresh_token")
        
        if [ -n "$TOKEN" ]; then
            echo "$TOKEN" > "$TOKEN_FILE"
            echo "$REFRESH_TOKEN" > "$REFRESH_TOKEN_FILE"
            export TOKEN
            log_info "Token 已保存到 $TOKEN_FILE"
            log_info "Refresh Token 已保存到 $REFRESH_TOKEN_FILE"
        else
            log_error "无法从响应中提取 token"
        fi
    else
        log_error "登录失败，无法继续测试"
        exit 1
    fi
    echo ""
    
    # 1.3 Token 刷新（可选）
    if [ -n "$REFRESH_TOKEN" ]; then
        log_info "Phase 1.3: Token 刷新"
        REFRESH_DATA="{
            \"refresh_token\": \"$REFRESH_TOKEN\"
        }"
        
        refresh_response=$(test_request "Token 刷新" "POST" "$BASE_URL/api/v1/auth/refresh" "$REFRESH_DATA" "200")
        
        if [ $? -eq 0 ]; then
            NEW_TOKEN=$(extract_json_value "$refresh_response" "access_token")
            if [ -n "$NEW_TOKEN" ]; then
                TOKEN="$NEW_TOKEN"
                echo "$TOKEN" > "$TOKEN_FILE"
                export TOKEN
                log_info "Token 已刷新并保存"
            fi
        fi
        echo ""
    fi
    
    # 测试总结
    echo ""
    log_info "=== 测试总结 ==="
    echo -e "${GREEN}通过: $PASSED${NC}"
    echo -e "${RED}失败: $FAILED${NC}"
    
    if [ $FAILED -eq 0 ]; then
        log_info "所有认证测试通过！"
        log_info "Token 已导出到环境变量 TOKEN"
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

