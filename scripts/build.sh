#!/usr/bin/env bash
# Qbitel EdgeOS Build Script
#
# Usage:
#   ./scripts/build.sh [target] [profile]
#
# Targets:
#   stm32h7  - STM32H7 (Cortex-M7)
#   stm32u5  - STM32U5 (Cortex-M33 with TrustZone)
#   riscv    - RISC-V (SiFive HiFive)
#   all      - Build all targets
#   native   - Build for host (testing only)
#
# Profiles:
#   debug    - Debug build with symbols
#   release  - Optimized release build
#
# Examples:
#   ./scripts/build.sh stm32h7 release
#   ./scripts/build.sh all release

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="${PROJECT_ROOT}/build"

# Target configurations
declare -A TARGETS=(
    ["stm32h7"]="thumbv7em-none-eabihf"
    ["stm32u5"]="thumbv8m.main-none-eabihf"
    ["riscv"]="riscv32imac-unknown-none-elf"
)

declare -A FEATURES=(
    ["stm32h7"]="stm32h7"
    ["stm32u5"]="stm32u5"
    ["riscv"]="riscv"
)

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
    exit 1
}

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."

    if ! command -v cargo &> /dev/null; then
        log_error "cargo not found. Please install Rust."
    fi

    if ! command -v rustup &> /dev/null; then
        log_error "rustup not found. Please install rustup."
    fi

    log_success "Prerequisites satisfied"
}

# Install target if not present
install_target() {
    local target="$1"

    if ! rustup target list --installed | grep -q "$target"; then
        log_info "Installing target: $target"
        rustup target add "$target"
    fi
}

# Build for a specific target
build_target() {
    local platform="$1"
    local profile="${2:-release}"

    local target="${TARGETS[$platform]}"
    local features="${FEATURES[$platform]}"

    if [[ -z "$target" ]]; then
        log_error "Unknown platform: $platform"
    fi

    log_info "Building for $platform ($target)..."

    # Install target if needed
    install_target "$target"

    # Create output directory
    local output_dir="${BUILD_DIR}/${platform}/${profile}"
    mkdir -p "$output_dir"

    # Build arguments
    local build_args=("--target" "$target" "--features" "$features")
    if [[ "$profile" == "release" ]]; then
        build_args+=("--release")
    fi

    # Build bootloader
    log_info "Building bootloader..."
    cargo build --package q-boot "${build_args[@]}"

    # Build kernel
    log_info "Building kernel..."
    cargo build --package q-kernel "${build_args[@]}"

    # Copy artifacts
    local target_dir="${PROJECT_ROOT}/target/${target}/${profile}"

    if [[ -f "${target_dir}/q-boot" ]]; then
        cp "${target_dir}/q-boot" "${output_dir}/bootloader.elf"
    fi

    if [[ -f "${target_dir}/q-kernel" ]]; then
        cp "${target_dir}/q-kernel" "${output_dir}/kernel.elf"
    fi

    # Generate binary files if llvm-tools are available
    if command -v rust-objcopy &> /dev/null; then
        log_info "Generating binary files..."

        if [[ -f "${output_dir}/bootloader.elf" ]]; then
            rust-objcopy -O binary "${output_dir}/bootloader.elf" "${output_dir}/bootloader.bin"
            rust-objcopy -O ihex "${output_dir}/bootloader.elf" "${output_dir}/bootloader.hex"
        fi

        if [[ -f "${output_dir}/kernel.elf" ]]; then
            rust-objcopy -O binary "${output_dir}/kernel.elf" "${output_dir}/kernel.bin"
            rust-objcopy -O ihex "${output_dir}/kernel.elf" "${output_dir}/kernel.hex"
        fi
    else
        log_warn "rust-objcopy not found. Install llvm-tools: rustup component add llvm-tools-preview"
    fi

    # Generate size report
    if command -v rust-size &> /dev/null; then
        log_info "Size report for $platform:"
        rust-size "${output_dir}"/*.elf 2>/dev/null || true
    fi

    log_success "Build complete for $platform: ${output_dir}"
}

# Build native (for testing)
build_native() {
    local profile="${1:-release}"

    log_info "Building native (host) target..."

    local build_args=("--workspace" "--all-features")
    if [[ "$profile" == "release" ]]; then
        build_args+=("--release")
    fi

    cargo build "${build_args[@]}"

    log_success "Native build complete"
}

# Build all targets
build_all() {
    local profile="${1:-release}"

    log_info "Building all targets..."

    for platform in "${!TARGETS[@]}"; do
        build_target "$platform" "$profile"
    done

    log_success "All targets built successfully"
}

# Print usage
usage() {
    echo "Qbitel EdgeOS Build Script"
    echo ""
    echo "Usage: $0 [target] [profile]"
    echo ""
    echo "Targets:"
    echo "  stm32h7  - STM32H7 (Cortex-M7)"
    echo "  stm32u5  - STM32U5 (Cortex-M33 with TrustZone)"
    echo "  riscv    - RISC-V (SiFive HiFive)"
    echo "  all      - Build all targets"
    echo "  native   - Build for host (testing only)"
    echo ""
    echo "Profiles:"
    echo "  debug    - Debug build with symbols"
    echo "  release  - Optimized release build (default)"
    echo ""
    echo "Examples:"
    echo "  $0 stm32h7 release"
    echo "  $0 all release"
}

# Main
main() {
    local target="${1:-}"
    local profile="${2:-release}"

    if [[ -z "$target" || "$target" == "-h" || "$target" == "--help" ]]; then
        usage
        exit 0
    fi

    cd "$PROJECT_ROOT"

    check_prerequisites

    case "$target" in
        stm32h7|stm32u5|riscv)
            build_target "$target" "$profile"
            ;;
        all)
            build_all "$profile"
            ;;
        native)
            build_native "$profile"
            ;;
        *)
            log_error "Unknown target: $target"
            ;;
    esac
}

main "$@"
