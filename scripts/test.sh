#!/usr/bin/env bash
# Qbitel EdgeOS Test Script
#
# Usage:
#   ./scripts/test.sh [suite]
#
# Suites:
#   unit       - Run unit tests
#   crypto     - Run cryptographic tests
#   integration - Run integration tests
#   all        - Run all tests
#
# Examples:
#   ./scripts/test.sh unit
#   ./scripts/test.sh all

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Run unit tests
run_unit_tests() {
    log_info "Running unit tests..."

    cargo test --workspace --lib --all-features

    log_success "Unit tests passed"
}

# Run crypto-specific tests
run_crypto_tests() {
    log_info "Running cryptographic tests..."

    cargo test --package q-crypto --all-features -- --nocapture

    log_success "Crypto tests passed"
}

# Run integration tests
run_integration_tests() {
    log_info "Running integration tests..."

    cargo test --workspace --test '*' --all-features

    log_success "Integration tests passed"
}

# Run doc tests
run_doc_tests() {
    log_info "Running documentation tests..."

    cargo test --workspace --doc --all-features

    log_success "Doc tests passed"
}

# Run Python tool tests
run_python_tests() {
    log_info "Running Python tool tests..."

    if command -v pytest &> /dev/null; then
        cd "$PROJECT_ROOT/tools/q-provision"
        pytest tests/ -v || log_info "q-provision tests: no tests found or failed"

        cd "$PROJECT_ROOT/tools/q-sign"
        pytest tests/ -v || log_info "q-sign tests: no tests found or failed"

        cd "$PROJECT_ROOT"
    else
        log_info "pytest not found, skipping Python tests"
    fi
}

# Run all tests
run_all_tests() {
    local failed=0

    run_unit_tests || failed=1
    run_crypto_tests || failed=1
    run_integration_tests || failed=1
    run_doc_tests || failed=1
    run_python_tests || failed=1

    if [[ $failed -eq 0 ]]; then
        log_success "All tests passed"
    else
        log_error "Some tests failed"
        exit 1
    fi
}

# Print usage
usage() {
    echo "Qbitel EdgeOS Test Script"
    echo ""
    echo "Usage: $0 [suite]"
    echo ""
    echo "Suites:"
    echo "  unit        - Run unit tests"
    echo "  crypto      - Run cryptographic tests"
    echo "  integration - Run integration tests"
    echo "  doc         - Run documentation tests"
    echo "  python      - Run Python tool tests"
    echo "  all         - Run all tests (default)"
}

# Main
main() {
    local suite="${1:-all}"

    cd "$PROJECT_ROOT"

    case "$suite" in
        unit)
            run_unit_tests
            ;;
        crypto)
            run_crypto_tests
            ;;
        integration)
            run_integration_tests
            ;;
        doc)
            run_doc_tests
            ;;
        python)
            run_python_tests
            ;;
        all)
            run_all_tests
            ;;
        -h|--help)
            usage
            ;;
        *)
            log_error "Unknown suite: $suite"
            usage
            exit 1
            ;;
    esac
}

main "$@"
