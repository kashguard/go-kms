#!/bin/bash
# KMS API 完整测试脚本
# 整合所有测试脚本，按顺序执行完整的测试流程

set -e

# 配置
BASE_URL="${BASE_URL:-http://localhost:8080}"
VERBOSE="${VERBOSE:-false}"
TESTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 测试计数器
TOTAL_PASSED=0
TOTAL_FAILED=0
TEST_SUITES=0

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

log_section() {
    echo ""
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}========================================${NC}"
    echo ""
}

# 运行测试脚本
run_test_script() {
    local script_name="$1"
    local script_path="$TESTS_DIR/$script_name"
    
    if [ ! -f "$script_path" ]; then
        log_error "测试脚本不存在: $script_path"
        return 1
    fi
    
    log_info "运行测试: $script_name"
    
    local start_time=$(date +%s)
    local exit_code=0
    
    if [ "$VERBOSE" = "true" ]; then
        bash "$script_path" -u "$BASE_URL" -v || exit_code=$?
    else
        bash "$script_path" -u "$BASE_URL" || exit_code=$?
    fi
    
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    
    ((TEST_SUITES++))
    
    if [ $exit_code -eq 0 ]; then
        log_info "✓ $script_name 完成 (${duration}s)"
        ((TOTAL_PASSED++))
        return 0
    else
        log_error "✗ $script_name 失败 (${duration}s)"
        ((TOTAL_FAILED++))
        return 1
    fi
}

# 主测试流程
main() {
    log_section "KMS API 完整测试套件"
    log_info "Base URL: $BASE_URL"
    log_info "Tests Directory: $TESTS_DIR"
    log_info "Verbose: $VERBOSE"
    echo ""
    
    local overall_start_time=$(date +%s)
    
    # Phase 1: 用户认证流程
    log_section "Phase 1: 用户认证流程"
    run_test_script "test-auth.sh"
    
    # 检查 token 是否成功获取
    if [ ! -f "/tmp/kms_test_token.txt" ]; then
        log_error "认证失败，无法获取 token，停止测试"
        exit 1
    fi
    
    # Phase 2: KMS 密钥管理
    log_section "Phase 2: KMS 密钥管理"
    run_test_script "test-keys.sh"
    
    # Phase 3: KMS 加密解密
    log_section "Phase 3: KMS 加密解密"
    run_test_script "test-encryption.sh"
    
    # Phase 4: KMS 签名验证
    log_section "Phase 4: KMS 签名验证"
    run_test_script "test-signing.sh"
    
    # Phase 5: KMS 策略管理
    log_section "Phase 5: KMS 策略管理"
    run_test_script "test-policies.sh"
    
    # Phase 6: KMS 审计日志
    log_section "Phase 6: KMS 审计日志"
    run_test_script "test-audit.sh"
    
    # Phase 7: 错误场景测试
    log_section "Phase 7: 错误场景测试"
    run_test_script "test-errors.sh"
    
    local overall_end_time=$(date +%s)
    local overall_duration=$((overall_end_time - overall_start_time))
    
    # 测试总结
    log_section "测试总结"
    echo -e "${GREEN}通过的测试套件: $TOTAL_PASSED${NC}"
    echo -e "${RED}失败的测试套件: $TOTAL_FAILED${NC}"
    echo -e "总测试套件数: $TEST_SUITES"
    echo -e "总耗时: ${overall_duration}s"
    echo ""
    
    if [ $TOTAL_FAILED -eq 0 ]; then
        log_info "🎉 所有测试套件通过！"
        return 0
    else
        log_error "部分测试套件失败"
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

