# Qbitel EdgeOS Makefile
#
# Common targets:
#   make build          - Build for all targets
#   make build-stm32h7  - Build for STM32H7
#   make test           - Run all tests
#   make flash          - Flash to connected device
#   make clean          - Clean build artifacts

.PHONY: all build build-stm32h7 build-stm32u5 build-riscv build-native \
        test test-unit test-crypto check lint fmt doc clean flash help

# Default target
all: build

#
# Build targets
#

build: build-stm32h7 build-stm32u5 build-riscv
	@echo "All targets built successfully"

build-stm32h7:
	@./scripts/build.sh stm32h7 release

build-stm32u5:
	@./scripts/build.sh stm32u5 release

build-riscv:
	@./scripts/build.sh riscv release

build-native:
	@./scripts/build.sh native release

build-debug:
	@./scripts/build.sh stm32h7 debug

#
# Test targets
#

test:
	@./scripts/test.sh all

test-unit:
	@./scripts/test.sh unit

test-crypto:
	@./scripts/test.sh crypto

test-python:
	@./scripts/test.sh python

#
# Code quality
#

check:
	cargo check --workspace --all-features

lint:
	cargo clippy --workspace --all-features -- -D warnings

fmt:
	cargo fmt --all

fmt-check:
	cargo fmt --all -- --check

#
# Documentation
#

doc:
	cargo doc --workspace --no-deps --all-features

doc-open: doc
	cargo doc --workspace --no-deps --all-features --open

book:
	mdbook build docs/

book-serve:
	mdbook serve docs/ --open

#
# Flash targets
#

flash: flash-stm32h7

flash-stm32h7:
	@./scripts/flash.sh stm32h7 stlink all

flash-stm32u5:
	@./scripts/flash.sh stm32u5 stlink all

flash-bootloader:
	@./scripts/flash.sh stm32h7 stlink bootloader

flash-kernel:
	@./scripts/flash.sh stm32h7 stlink kernel

#
# Python tools
#

install-tools:
	pip install -e tools/q-provision
	pip install -e tools/q-sign

install-tools-dev:
	pip install -e tools/q-provision[dev]
	pip install -e tools/q-sign[dev]

#
# Cleanup
#

clean:
	cargo clean
	rm -rf build/
	rm -rf tools/q-provision/dist/
	rm -rf tools/q-sign/dist/
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name "*.egg-info" -exec rm -rf {} + 2>/dev/null || true

#
# Release
#

release-check:
	cargo publish --dry-run --package q-common
	cargo publish --dry-run --package q-crypto
	cargo publish --dry-run --package q-hal

#
# Security
#

audit:
	cargo audit

#
# Help
#

help:
	@echo "Qbitel EdgeOS Build System"
	@echo ""
	@echo "Build targets:"
	@echo "  make build          - Build for all embedded targets"
	@echo "  make build-stm32h7  - Build for STM32H7"
	@echo "  make build-stm32u5  - Build for STM32U5"
	@echo "  make build-riscv    - Build for RISC-V"
	@echo "  make build-native   - Build for host (testing)"
	@echo "  make build-debug    - Debug build for STM32H7"
	@echo ""
	@echo "Test targets:"
	@echo "  make test           - Run all tests"
	@echo "  make test-unit      - Run unit tests"
	@echo "  make test-crypto    - Run crypto tests"
	@echo "  make test-python    - Run Python tool tests"
	@echo ""
	@echo "Code quality:"
	@echo "  make check          - Check compilation"
	@echo "  make lint           - Run clippy linter"
	@echo "  make fmt            - Format code"
	@echo "  make fmt-check      - Check formatting"
	@echo ""
	@echo "Documentation:"
	@echo "  make doc            - Build API documentation (rustdoc)"
	@echo "  make doc-open       - Build and open API documentation"
	@echo "  make book           - Build documentation site (mdBook)"
	@echo "  make book-serve     - Serve documentation site locally"
	@echo ""
	@echo "Flash targets:"
	@echo "  make flash          - Flash to STM32H7 via ST-Link"
	@echo "  make flash-stm32h7  - Flash to STM32H7"
	@echo "  make flash-stm32u5  - Flash to STM32U5"
	@echo ""
	@echo "Python tools:"
	@echo "  make install-tools  - Install Python tools"
	@echo ""
	@echo "Other:"
	@echo "  make clean          - Clean build artifacts"
	@echo "  make audit          - Run security audit"
	@echo "  make help           - Show this help"
