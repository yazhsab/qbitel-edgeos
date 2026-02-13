#!/usr/bin/env bash
# Qbitel EdgeOS Flash Script
#
# Usage:
#   ./scripts/flash.sh [target] [probe] [component]
#
# Targets:
#   stm32h7  - STM32H7 (Cortex-M7)
#   stm32u5  - STM32U5 (Cortex-M33 with TrustZone)
#   riscv    - RISC-V (SiFive HiFive)
#
# Probes:
#   stlink   - ST-Link debugger
#   jlink    - J-Link debugger
#   openocd  - OpenOCD (generic)
#
# Components:
#   bootloader - Flash bootloader only
#   kernel     - Flash kernel only
#   all        - Flash all components
#
# Examples:
#   ./scripts/flash.sh stm32h7 stlink all
#   ./scripts/flash.sh stm32h7 jlink bootloader

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="${PROJECT_ROOT}/build"

# Memory addresses
declare -A BOOTLOADER_ADDR=(
    ["stm32h7"]="0x08000000"
    ["stm32u5"]="0x08000000"
    ["riscv"]="0x20000000"
)

declare -A KERNEL_ADDR=(
    ["stm32h7"]="0x08008000"
    ["stm32u5"]="0x08008000"
    ["riscv"]="0x20008000"
)

# OpenOCD configurations
declare -A OPENOCD_CFG=(
    ["stm32h7"]="interface/stlink.cfg target/stm32h7x.cfg"
    ["stm32u5"]="interface/stlink.cfg target/stm32u5x.cfg"
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

# Flash with ST-Link
flash_stlink() {
    local target="$1"
    local component="$2"
    local binary_dir="${BUILD_DIR}/${target}/release"

    if ! command -v st-flash &> /dev/null; then
        log_error "st-flash not found. Install stlink-tools."
    fi

    if [[ "$component" == "bootloader" || "$component" == "all" ]]; then
        local bootloader="${binary_dir}/bootloader.bin"
        local addr="${BOOTLOADER_ADDR[$target]}"

        if [[ ! -f "$bootloader" ]]; then
            log_error "Bootloader binary not found: $bootloader"
        fi

        log_info "Flashing bootloader to ${addr}..."
        st-flash write "$bootloader" "$addr"
        log_success "Bootloader flashed"
    fi

    if [[ "$component" == "kernel" || "$component" == "all" ]]; then
        local kernel="${binary_dir}/kernel.bin"
        local addr="${KERNEL_ADDR[$target]}"

        if [[ ! -f "$kernel" ]]; then
            log_error "Kernel binary not found: $kernel"
        fi

        log_info "Flashing kernel to ${addr}..."
        st-flash write "$kernel" "$addr"
        log_success "Kernel flashed"
    fi
}

# Flash with J-Link
flash_jlink() {
    local target="$1"
    local component="$2"
    local binary_dir="${BUILD_DIR}/${target}/release"

    if ! command -v JLinkExe &> /dev/null; then
        log_error "JLinkExe not found. Install J-Link software."
    fi

    # Create JLink script
    local jlink_script=$(mktemp)
    trap "rm -f $jlink_script" EXIT

    # Determine device name
    local device=""
    case "$target" in
        stm32h7) device="STM32H743ZI" ;;
        stm32u5) device="STM32U575ZI" ;;
        *) log_error "J-Link not supported for target: $target" ;;
    esac

    cat > "$jlink_script" << EOF
si 1
speed 4000
r
h
EOF

    if [[ "$component" == "bootloader" || "$component" == "all" ]]; then
        local bootloader="${binary_dir}/bootloader.bin"
        local addr="${BOOTLOADER_ADDR[$target]}"

        if [[ ! -f "$bootloader" ]]; then
            log_error "Bootloader binary not found: $bootloader"
        fi

        echo "loadbin $bootloader, $addr" >> "$jlink_script"
    fi

    if [[ "$component" == "kernel" || "$component" == "all" ]]; then
        local kernel="${binary_dir}/kernel.bin"
        local addr="${KERNEL_ADDR[$target]}"

        if [[ ! -f "$kernel" ]]; then
            log_error "Kernel binary not found: $kernel"
        fi

        echo "loadbin $kernel, $addr" >> "$jlink_script"
    fi

    cat >> "$jlink_script" << EOF
r
g
exit
EOF

    log_info "Flashing via J-Link..."
    JLinkExe -device "$device" -if SWD -speed 4000 -autoconnect 1 -CommanderScript "$jlink_script"
    log_success "Flash complete"
}

# Flash with OpenOCD
flash_openocd() {
    local target="$1"
    local component="$2"
    local binary_dir="${BUILD_DIR}/${target}/release"

    if ! command -v openocd &> /dev/null; then
        log_error "openocd not found. Install OpenOCD."
    fi

    local cfg="${OPENOCD_CFG[$target]:-}"
    if [[ -z "$cfg" ]]; then
        log_error "OpenOCD configuration not available for target: $target"
    fi

    local commands=""

    if [[ "$component" == "bootloader" || "$component" == "all" ]]; then
        local bootloader="${binary_dir}/bootloader.bin"
        local addr="${BOOTLOADER_ADDR[$target]}"

        if [[ ! -f "$bootloader" ]]; then
            log_error "Bootloader binary not found: $bootloader"
        fi

        commands+="flash write_image erase $bootloader $addr bin; "
    fi

    if [[ "$component" == "kernel" || "$component" == "all" ]]; then
        local kernel="${binary_dir}/kernel.bin"
        local addr="${KERNEL_ADDR[$target]}"

        if [[ ! -f "$kernel" ]]; then
            log_error "Kernel binary not found: $kernel"
        fi

        commands+="flash write_image erase $kernel $addr bin; "
    fi

    commands+="reset run; shutdown"

    log_info "Flashing via OpenOCD..."
    # shellcheck disable=SC2086
    openocd -f $cfg -c "init; $commands"
    log_success "Flash complete"
}

# Print usage
usage() {
    echo "Qbitel EdgeOS Flash Script"
    echo ""
    echo "Usage: $0 [target] [probe] [component]"
    echo ""
    echo "Targets:"
    echo "  stm32h7  - STM32H7 (Cortex-M7)"
    echo "  stm32u5  - STM32U5 (Cortex-M33)"
    echo "  riscv    - RISC-V"
    echo ""
    echo "Probes:"
    echo "  stlink   - ST-Link debugger"
    echo "  jlink    - J-Link debugger"
    echo "  openocd  - OpenOCD (generic)"
    echo ""
    echo "Components:"
    echo "  bootloader - Flash bootloader only"
    echo "  kernel     - Flash kernel only"
    echo "  all        - Flash all components (default)"
    echo ""
    echo "Examples:"
    echo "  $0 stm32h7 stlink all"
    echo "  $0 stm32h7 jlink bootloader"
}

# Main
main() {
    local target="${1:-}"
    local probe="${2:-stlink}"
    local component="${3:-all}"

    if [[ -z "$target" || "$target" == "-h" || "$target" == "--help" ]]; then
        usage
        exit 0
    fi

    cd "$PROJECT_ROOT"

    case "$probe" in
        stlink)
            flash_stlink "$target" "$component"
            ;;
        jlink)
            flash_jlink "$target" "$component"
            ;;
        openocd)
            flash_openocd "$target" "$component"
            ;;
        *)
            log_error "Unknown probe: $probe"
            ;;
    esac
}

main "$@"
