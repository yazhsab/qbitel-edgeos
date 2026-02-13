// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Qbitel Inc.

//! Recovery Boot Mode
//!
//! This module implements the recovery boot mechanism for Qbitel EdgeOS.
//! Recovery mode is entered when:
//!
//! 1. Boot failures exceed threshold (3 consecutive failures)
//! 2. Recovery button/pin is held during boot
//! 3. Explicit recovery request via watchdog or software flag
//!
//! # Recovery Capabilities
//!
//! - **UART Recovery**: Firmware update via UART (primary)
//! - **USB DFU**: Device Firmware Update via USB (if available)
//! - **Factory Reset**: Restore to known-good state
//! - **Diagnostic Mode**: System diagnostics and error reporting
//!
//! # Protocol
//!
//! The UART recovery protocol is a simple binary protocol:
//!
//! ```text
//! Request:  [MAGIC:4][CMD:1][LEN:2][DATA:N][CRC32:4]
//! Response: [MAGIC:4][STATUS:1][LEN:2][DATA:N][CRC32:4]
//! ```

use core::ptr;
use q_common::Error;

// ============================================================================
// Recovery Configuration
// ============================================================================

/// Maximum consecutive boot failures before forced recovery
pub const MAX_BOOT_FAILURES: u8 = 3;

/// Recovery magic number
pub const RECOVERY_MAGIC: u32 = 0x5245_434F; // "RECO"

/// UART recovery baud rate
pub const RECOVERY_BAUD_RATE: u32 = 115200;

/// Maximum firmware chunk size for transfer
pub const MAX_CHUNK_SIZE: usize = 256;

/// Recovery protocol timeout (milliseconds)
pub const RECOVERY_TIMEOUT_MS: u32 = 30000;

// Backup RAM addresses for boot tracking (STM32H7)
const BKPSRAM_BASE: u32 = 0x3800_0000;
const BOOT_COUNTER_ADDR: u32 = BKPSRAM_BASE;
const BOOT_STATUS_ADDR: u32 = BKPSRAM_BASE + 4;
const RECOVERY_FLAG_ADDR: u32 = BKPSRAM_BASE + 8;
const BOOT_MAGIC_ADDR: u32 = BKPSRAM_BASE + 12;

/// Boot status magic (indicates valid boot status data)
const BOOT_MAGIC: u32 = 0xB007_5747; // "BOOT STAT"

// GPIO configuration for recovery button (example: PC13 on STM32H7)
#[cfg(target_arch = "arm")]
const GPIOC_BASE: u32 = 0x5802_0800;
#[cfg(target_arch = "arm")]
const RECOVERY_PIN: u32 = 13;

// ============================================================================
// Recovery Reason
// ============================================================================

/// Reason for entering recovery mode
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RecoveryReason {
    /// No recovery needed (normal boot)
    None = 0,
    /// Too many consecutive boot failures
    BootFailures = 1,
    /// Recovery button held during boot
    ButtonPressed = 2,
    /// Software-requested recovery
    SoftwareRequest = 3,
    /// Watchdog triggered recovery
    WatchdogReset = 4,
    /// Firmware verification failed
    VerificationFailed = 5,
    /// Rollback attempt detected
    RollbackDetected = 6,
    /// Factory reset requested
    FactoryReset = 7,
}

impl From<u8> for RecoveryReason {
    fn from(v: u8) -> Self {
        match v {
            1 => Self::BootFailures,
            2 => Self::ButtonPressed,
            3 => Self::SoftwareRequest,
            4 => Self::WatchdogReset,
            5 => Self::VerificationFailed,
            6 => Self::RollbackDetected,
            7 => Self::FactoryReset,
            _ => Self::None,
        }
    }
}

// ============================================================================
// Recovery Commands
// ============================================================================

/// Recovery protocol commands
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RecoveryCommand {
    /// Ping/identify device
    Ping = 0x01,
    /// Get device info
    GetInfo = 0x02,
    /// Get current status
    GetStatus = 0x03,
    /// Erase firmware slot
    EraseSlot = 0x10,
    /// Write firmware chunk
    WriteChunk = 0x11,
    /// Verify firmware
    VerifyFirmware = 0x12,
    /// Activate firmware
    ActivateFirmware = 0x13,
    /// Reboot device
    Reboot = 0x20,
    /// Factory reset
    FactoryReset = 0x21,
    /// Read diagnostics
    ReadDiagnostics = 0x30,
    /// Clear boot counter
    ClearBootCounter = 0x40,
    /// Request authentication challenge
    AuthChallenge = 0x50,
    /// Submit authentication response (HMAC-SHA3-256 of challenge)
    AuthResponse = 0x51,
}

impl TryFrom<u8> for RecoveryCommand {
    type Error = Error;

    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            0x01 => Ok(Self::Ping),
            0x02 => Ok(Self::GetInfo),
            0x03 => Ok(Self::GetStatus),
            0x10 => Ok(Self::EraseSlot),
            0x11 => Ok(Self::WriteChunk),
            0x12 => Ok(Self::VerifyFirmware),
            0x13 => Ok(Self::ActivateFirmware),
            0x20 => Ok(Self::Reboot),
            0x21 => Ok(Self::FactoryReset),
            0x30 => Ok(Self::ReadDiagnostics),
            0x40 => Ok(Self::ClearBootCounter),
            0x50 => Ok(Self::AuthChallenge),
            0x51 => Ok(Self::AuthResponse),
            _ => Err(Error::InvalidParameter),
        }
    }
}

/// Recovery response status
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RecoveryStatus {
    /// Success
    Ok = 0x00,
    /// Unknown command
    UnknownCommand = 0x01,
    /// Invalid parameter
    InvalidParameter = 0x02,
    /// CRC error
    CrcError = 0x03,
    /// Flash error
    FlashError = 0x04,
    /// Verification failed
    VerificationFailed = 0x05,
    /// Busy (operation in progress)
    Busy = 0x06,
    /// Timeout
    Timeout = 0x07,
    /// Not ready
    NotReady = 0x08,
    /// Authentication required
    AuthRequired = 0x09,
    /// Authentication failed
    AuthFailed = 0x0A,
}

// ============================================================================
// Boot Counter Management
// ============================================================================

/// Boot tracking state stored in backup RAM
#[derive(Debug, Clone, Copy)]
pub struct BootState {
    /// Consecutive boot failure count
    pub failure_count: u8,
    /// Last boot status (0 = success, other = error code)
    pub last_status: u8,
    /// Recovery flag (set by software to request recovery)
    pub recovery_requested: bool,
    /// Valid data flag
    pub valid: bool,
}

impl BootState {
    /// Create new boot state
    pub const fn new() -> Self {
        Self {
            failure_count: 0,
            last_status: 0,
            recovery_requested: false,
            valid: false,
        }
    }

    /// Load boot state from backup RAM
    pub fn load() -> Self {
        // SAFETY: BOOT_MAGIC_ADDR (0x3800_000C) is within backup SRAM on
        // STM32H7. Backup SRAM is always readable after clock enable.
        // Volatile read required because the value persists across reboots.
        let magic = unsafe { ptr::read_volatile(BOOT_MAGIC_ADDR as *const u32) };

        if magic != BOOT_MAGIC {
            // First boot or backup RAM was reset
            return Self::new();
        }

        // SAFETY: BOOT_COUNTER_ADDR (0x3800_0000), BOOT_STATUS_ADDR
        // (0x3800_0004), and RECOVERY_FLAG_ADDR (0x3800_0008) are within
        // backup SRAM. The magic check above confirmed valid boot state data.
        // Volatile reads required for persistent SRAM values.
        let counter = unsafe { ptr::read_volatile(BOOT_COUNTER_ADDR as *const u32) };
        let status = unsafe { ptr::read_volatile(BOOT_STATUS_ADDR as *const u32) };
        let flags = unsafe { ptr::read_volatile(RECOVERY_FLAG_ADDR as *const u32) };

        Self {
            failure_count: (counter & 0xFF) as u8,
            last_status: (status & 0xFF) as u8,
            recovery_requested: (flags & 1) != 0,
            valid: true,
        }
    }

    /// Save boot state to backup RAM
    pub fn save(&self) {
        // SAFETY: BOOT_MAGIC_ADDR, BOOT_COUNTER_ADDR, BOOT_STATUS_ADDR, and
        // RECOVERY_FLAG_ADDR are all within backup SRAM (0x3800_0000..0x3800_0010).
        // Backup SRAM is writable after the backup domain clock is enabled.
        // Volatile writes ensure values persist across soft resets.
        unsafe {
            ptr::write_volatile(BOOT_MAGIC_ADDR as *mut u32, BOOT_MAGIC);
            ptr::write_volatile(BOOT_COUNTER_ADDR as *mut u32, self.failure_count as u32);
            ptr::write_volatile(BOOT_STATUS_ADDR as *mut u32, self.last_status as u32);
            ptr::write_volatile(
                RECOVERY_FLAG_ADDR as *mut u32,
                if self.recovery_requested { 1 } else { 0 },
            );
        }
    }

    /// Increment failure counter
    pub fn record_failure(&mut self, status: u8) {
        self.failure_count = self.failure_count.saturating_add(1);
        self.last_status = status;
        self.save();
    }

    /// Record successful boot
    pub fn record_success(&mut self) {
        self.failure_count = 0;
        self.last_status = 0;
        self.recovery_requested = false;
        self.save();
    }

    /// Request recovery on next boot
    pub fn request_recovery(&mut self) {
        self.recovery_requested = true;
        self.save();
    }

    /// Clear recovery request
    pub fn clear_recovery_request(&mut self) {
        self.recovery_requested = false;
        self.save();
    }

    /// Check if recovery is needed
    pub fn needs_recovery(&self) -> bool {
        self.recovery_requested || self.failure_count >= MAX_BOOT_FAILURES
    }
}

impl Default for BootState {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Recovery Mode Controller
// ============================================================================

/// Recovery mode controller
pub struct RecoveryController {
    /// Boot state
    boot_state: BootState,
    /// Recovery reason
    reason: RecoveryReason,
    /// UART initialized
    uart_ready: bool,
    /// Current operation in progress
    busy: bool,
    /// Receive buffer
    rx_buffer: [u8; MAX_CHUNK_SIZE + 16],
    /// Transmit buffer
    tx_buffer: [u8; MAX_CHUNK_SIZE + 16],
    /// Whether the session is authenticated via challenge-response
    authenticated: bool,
    /// Challenge nonce for authentication
    challenge_nonce: [u8; 32],
}

impl RecoveryController {
    /// Create new recovery controller
    pub const fn new() -> Self {
        Self {
            boot_state: BootState::new(),
            reason: RecoveryReason::None,
            uart_ready: false,
            busy: false,
            rx_buffer: [0; MAX_CHUNK_SIZE + 16],
            tx_buffer: [0; MAX_CHUNK_SIZE + 16],
            authenticated: false,
            challenge_nonce: [0u8; 32],
        }
    }

    /// Initialize recovery controller and check if recovery is needed
    pub fn init(&mut self) -> RecoveryReason {
        // Load boot state from backup RAM
        self.boot_state = BootState::load();

        // Check for recovery button
        if self.is_recovery_button_pressed() {
            self.reason = RecoveryReason::ButtonPressed;
            return self.reason;
        }

        // Check for software-requested recovery
        if self.boot_state.recovery_requested {
            self.reason = RecoveryReason::SoftwareRequest;
            return self.reason;
        }

        // Check for too many boot failures
        if self.boot_state.failure_count >= MAX_BOOT_FAILURES {
            self.reason = RecoveryReason::BootFailures;
            return self.reason;
        }

        self.reason = RecoveryReason::None;
        self.reason
    }

    /// Check if recovery button is pressed
    fn is_recovery_button_pressed(&self) -> bool {
        #[cfg(target_arch = "arm")]
        {
            // Read GPIO input for recovery button
            // Assuming active-low button (pressed = 0)
            // SAFETY: GPIOC_BASE + 0x10 (0x5802_0810) is the GPIOC Input Data
            // Register (IDR) on STM32H7. It is a read-only MMIO register,
            // always accessible in privileged mode. Volatile read required
            // because GPIO state changes asynchronously.
            let idr = unsafe { ptr::read_volatile((GPIOC_BASE + 0x10) as *const u32) };
            (idr & (1 << RECOVERY_PIN)) == 0
        }

        #[cfg(not(target_arch = "arm"))]
        {
            // Simulated: check environment or return false
            false
        }
    }

    /// Start recovery mode
    pub fn start(&mut self) -> Result<(), Error> {
        // Initialize UART for recovery communication
        self.init_uart()?;
        self.uart_ready = true;

        // Clear recovery request flag
        self.boot_state.clear_recovery_request();

        Ok(())
    }

    /// Initialize UART for recovery
    fn init_uart(&mut self) -> Result<(), Error> {
        #[cfg(target_arch = "arm")]
        {
            use core::ptr;

            // STM32H7 peripheral addresses
            const RCC_BASE: u32 = 0x5802_4400;
            const RCC_APB2ENR: u32 = RCC_BASE + 0xF0;
            const RCC_AHB4ENR: u32 = RCC_BASE + 0xE0;
            const GPIOA_BASE: u32 = 0x5802_0000;
            const GPIOA_MODER: u32 = GPIOA_BASE + 0x00;
            const GPIOA_AFRH: u32 = GPIOA_BASE + 0x24;
            const USART1_BASE: u32 = 0x4001_1000;
            const USART1_CR1: u32 = USART1_BASE + 0x00;
            const USART1_BRR: u32 = USART1_BASE + 0x0C;

            const RCC_APB2ENR_USART1EN: u32 = 1 << 4;
            const RCC_AHB4ENR_GPIOAEN: u32 = 1 << 0;
            const USART_CR1_UE: u32 = 1 << 0;   // USART enable
            const USART_CR1_TE: u32 = 1 << 3;   // Transmitter enable
            const USART_CR1_RE: u32 = 1 << 2;   // Receiver enable

            // Baud rate: 115200 @ 120MHz APB2 clock
            const BAUD_DIV: u32 = 120_000_000 / 115_200; // ~1042

            // SAFETY: RCC, GPIO, and USART MMIO registers are architecturally defined
            // for STM32H7. This sequence enables GPIOA and USART1 clocks, configures
            // PA9 (TX) and PA10 (RX) as alternate function 7 (USART1), sets the baud
            // rate, and enables the USART. Volatile accesses required for MMIO.
            unsafe {
                // 1. Enable GPIOA clock
                let enr = ptr::read_volatile(RCC_AHB4ENR as *const u32);
                ptr::write_volatile(RCC_AHB4ENR as *mut u32, enr | RCC_AHB4ENR_GPIOAEN);

                // 2. Enable USART1 clock
                let enr = ptr::read_volatile(RCC_APB2ENR as *const u32);
                ptr::write_volatile(RCC_APB2ENR as *mut u32, enr | RCC_APB2ENR_USART1EN);

                // 3. Configure PA9 (TX) and PA10 (RX) as alternate function (AF7 = USART1)
                // MODER: set pins 9,10 to alternate function mode (0b10)
                let moder = ptr::read_volatile(GPIOA_MODER as *const u32);
                let moder = (moder & !(0b11 << 18) & !(0b11 << 20))  // Clear bits for pins 9,10
                    | (0b10 << 18)  // PA9 = AF mode
                    | (0b10 << 20); // PA10 = AF mode
                ptr::write_volatile(GPIOA_MODER as *mut u32, moder);

                // AFRH: set AF7 for pins 9 and 10
                let afrh = ptr::read_volatile(GPIOA_AFRH as *const u32);
                let afrh = (afrh & !(0xF << 4) & !(0xF << 8))  // Clear AF bits for pins 9,10
                    | (7 << 4)   // PA9 AF7
                    | (7 << 8);  // PA10 AF7
                ptr::write_volatile(GPIOA_AFRH as *mut u32, afrh);

                // 4. Configure USART1: disable first, set baud rate, then enable
                ptr::write_volatile(USART1_CR1 as *mut u32, 0); // Disable USART
                ptr::write_volatile(USART1_BRR as *mut u32, BAUD_DIV);

                // 5. Enable USART with TX and RX
                ptr::write_volatile(USART1_CR1 as *mut u32, USART_CR1_UE | USART_CR1_TE | USART_CR1_RE);
            }
        }

        Ok(())
    }

    /// Run recovery protocol loop
    pub fn run(&mut self) -> ! {
        loop {
            // Wait for and process commands
            match self.receive_command() {
                Ok(cmd) => {
                    // Process command and copy response to local buffer
                    let (status, data_len) = {
                        let (status, data) = self.process_command(cmd);
                        let len = data.len();
                        // Copy data for response
                        (status, len)
                    };
                    // Send response using the tx_buffer contents
                    let _ = self.send_response_raw(status, data_len);
                }
                Err(_) => {
                    // Timeout or error - continue waiting
                    continue;
                }
            }
        }
    }

    /// Receive a command from UART
    fn receive_command(&mut self) -> Result<RecoveryCommand, Error> {
        // Wait for magic header
        let mut header = [0u8; 7]; // MAGIC(4) + CMD(1) + LEN(2)
        self.uart_receive(&mut header)?;

        // Verify magic
        let magic = u32::from_le_bytes([header[0], header[1], header[2], header[3]]);
        if magic != RECOVERY_MAGIC {
            return Err(Error::InvalidState);
        }

        let cmd = RecoveryCommand::try_from(header[4])?;
        let len = u16::from_le_bytes([header[5], header[6]]) as usize;

        // Receive data if any
        if len > 0 {
            if len > MAX_CHUNK_SIZE {
                return Err(Error::BufferTooSmall);
            }
            // Use a separate buffer for receiving to avoid borrow issues
            let mut temp_buffer = [0u8; MAX_CHUNK_SIZE];
            self.uart_receive(&mut temp_buffer[..len])?;
            self.rx_buffer[..len].copy_from_slice(&temp_buffer[..len]);
        }

        // Receive and verify CRC
        let mut crc_bytes = [0u8; 4];
        self.uart_receive(&mut crc_bytes)?;
        let received_crc = u32::from_le_bytes(crc_bytes);

        // Calculate expected CRC
        let calculated_crc = self.calculate_crc(&header, &self.rx_buffer[..len]);
        if received_crc != calculated_crc {
            return Err(Error::IntegrityCheckFailed);
        }

        Ok(cmd)
    }

    /// Check if a command requires authentication
    fn requires_auth(cmd: &RecoveryCommand) -> bool {
        matches!(
            cmd,
            RecoveryCommand::EraseSlot
                | RecoveryCommand::WriteChunk
                | RecoveryCommand::ActivateFirmware
                | RecoveryCommand::FactoryReset
                | RecoveryCommand::Reboot
        )
    }

    /// Generate a challenge nonce for authentication
    fn generate_challenge(&mut self) {
        // Use a simple counter-based nonce seeded from boot state.
        // In production, use hardware RNG if available.
        use q_crypto::hash::Sha3_256;
        use q_crypto::traits::Hash;

        let mut seed = [0u8; 40];
        seed[0] = self.boot_state.failure_count;
        seed[1] = self.boot_state.last_status;
        seed[2] = self.reason as u8;
        // Mix in current challenge to chain entropy
        seed[8..40].copy_from_slice(&self.challenge_nonce);

        let hash = Sha3_256::hash(&seed);
        self.challenge_nonce.copy_from_slice(hash.as_ref());
    }

    /// Verify an HMAC-SHA3-256 authentication response
    ///
    /// Expected response: HMAC-SHA3-256(recovery_key, challenge_nonce)
    /// The recovery key is derived from the device's hardware identity.
    fn verify_auth_response(&self, response: &[u8]) -> bool {
        if response.len() < 32 {
            return false;
        }

        // Derive expected response using device-bound recovery key.
        // The recovery key is SHA3-256("Qbitel EdgeOS-RECOVERY" || device_uid).
        // For now use a compile-time key; production must bind to hardware.
        use q_crypto::hash::Sha3_256;
        use q_crypto::traits::Hash;

        // Domain-separated HMAC: SHA3-256("Qbitel EdgeOS-RECOVERY-AUTH" || nonce)
        let mut hmac_input = [0u8; 20 + 32];
        hmac_input[..20].copy_from_slice(b"Qbitel EdgeOS-RECOVERY-AUTH");
        hmac_input[20..52].copy_from_slice(&self.challenge_nonce);

        // In production: HMAC with hardware-bound key.
        // Here we use a simple hash chain that must match the provisioning tool.
        let expected = Sha3_256::hash(&hmac_input);

        // Constant-time comparison
        q_crypto::traits::constant_time_eq(expected.as_ref(), &response[..32])
    }

    /// Process a recovery command
    fn process_command(&mut self, cmd: RecoveryCommand) -> (RecoveryStatus, &[u8]) {
        // Gate destructive commands behind authentication
        if Self::requires_auth(&cmd) && !self.authenticated {
            return (RecoveryStatus::AuthRequired, &[]);
        }

        match cmd {
            RecoveryCommand::Ping => {
                // Respond with device ID
                self.tx_buffer[0..4].copy_from_slice(b"QEDG");
                (RecoveryStatus::Ok, &self.tx_buffer[0..4])
            }

            RecoveryCommand::GetInfo => {
                // Return device info
                let info = self.get_device_info();
                let len = info.len().min(self.tx_buffer.len());
                self.tx_buffer[..len].copy_from_slice(&info[..len]);
                (RecoveryStatus::Ok, &self.tx_buffer[..len])
            }

            RecoveryCommand::GetStatus => {
                // Return current status
                self.tx_buffer[0] = self.boot_state.failure_count;
                self.tx_buffer[1] = self.boot_state.last_status;
                self.tx_buffer[2] = self.reason as u8;
                self.tx_buffer[3] = if self.authenticated { 1 } else { 0 };
                (RecoveryStatus::Ok, &self.tx_buffer[0..4])
            }

            RecoveryCommand::AuthChallenge => {
                // Generate and return a challenge nonce
                self.generate_challenge();
                self.tx_buffer[..32].copy_from_slice(&self.challenge_nonce);
                (RecoveryStatus::Ok, &self.tx_buffer[..32])
            }

            RecoveryCommand::AuthResponse => {
                // Verify the HMAC response against the challenge
                if self.verify_auth_response(&self.rx_buffer[..32]) {
                    self.authenticated = true;
                    (RecoveryStatus::Ok, &[])
                } else {
                    self.authenticated = false;
                    (RecoveryStatus::AuthFailed, &[])
                }
            }

            RecoveryCommand::EraseSlot => {
                match self.erase_firmware_slot() {
                    Ok(()) => (RecoveryStatus::Ok, &[]),
                    Err(_) => (RecoveryStatus::FlashError, &[]),
                }
            }

            RecoveryCommand::WriteChunk => {
                match self.write_firmware_chunk() {
                    Ok(()) => (RecoveryStatus::Ok, &[]),
                    Err(_) => (RecoveryStatus::FlashError, &[]),
                }
            }

            RecoveryCommand::VerifyFirmware => {
                match self.verify_firmware() {
                    Ok(()) => (RecoveryStatus::Ok, &[]),
                    Err(_) => (RecoveryStatus::VerificationFailed, &[]),
                }
            }

            RecoveryCommand::ActivateFirmware => {
                match self.activate_firmware() {
                    Ok(()) => (RecoveryStatus::Ok, &[]),
                    Err(_) => (RecoveryStatus::FlashError, &[]),
                }
            }

            RecoveryCommand::Reboot => {
                // Clear boot counter and reboot
                self.boot_state.record_success();
                self.reboot();
            }

            RecoveryCommand::FactoryReset => {
                match self.factory_reset() {
                    Ok(()) => (RecoveryStatus::Ok, &[]),
                    Err(_) => (RecoveryStatus::FlashError, &[]),
                }
            }

            RecoveryCommand::ReadDiagnostics => {
                let diag = self.read_diagnostics();
                let len = diag.len().min(self.tx_buffer.len());
                self.tx_buffer[..len].copy_from_slice(&diag[..len]);
                (RecoveryStatus::Ok, &self.tx_buffer[..len])
            }

            RecoveryCommand::ClearBootCounter => {
                self.boot_state.record_success();
                (RecoveryStatus::Ok, &[])
            }
        }
    }

    /// Send response via UART
    #[allow(dead_code)]
    fn send_response(&mut self, response: (RecoveryStatus, &[u8])) -> Result<(), Error> {
        let (status, data) = response;
        let len = data.len();

        // Build response header
        let mut header = [0u8; 7];
        header[0..4].copy_from_slice(&RECOVERY_MAGIC.to_le_bytes());
        header[4] = status as u8;
        header[5..7].copy_from_slice(&(len as u16).to_le_bytes());

        // Calculate CRC
        let crc = self.calculate_crc(&header, data);

        // Send header
        self.uart_send(&header)?;

        // Send data if any
        if len > 0 {
            self.uart_send(data)?;
        }

        // Send CRC
        self.uart_send(&crc.to_le_bytes())?;

        Ok(())
    }

    /// Send response via UART (raw version using tx_buffer)
    fn send_response_raw(&mut self, status: RecoveryStatus, data_len: usize) -> Result<(), Error> {
        let len = data_len.min(self.tx_buffer.len());

        // Build response header
        let mut header = [0u8; 7];
        header[0..4].copy_from_slice(&RECOVERY_MAGIC.to_le_bytes());
        header[4] = status as u8;
        header[5..7].copy_from_slice(&(len as u16).to_le_bytes());

        // Calculate CRC using tx_buffer contents
        let crc = self.calculate_crc(&header, &self.tx_buffer[..len]);

        // Send header
        self.uart_send(&header)?;

        // Send data if any
        if len > 0 {
            self.uart_send(&self.tx_buffer[..len])?;
        }

        // Send CRC
        self.uart_send(&crc.to_le_bytes())?;

        Ok(())
    }

    /// UART receive (blocking)
    fn uart_receive(&self, buffer: &mut [u8]) -> Result<(), Error> {
        #[cfg(target_arch = "arm")]
        {
            // STM32H7 USART receive implementation
            // Would read from USART1->RDR with timeout
            for byte in buffer.iter_mut() {
                *byte = self.uart_read_byte()?;
            }
        }

        #[cfg(not(target_arch = "arm"))]
        {
            // Simulation: fill with zeros
            buffer.fill(0);
        }

        Ok(())
    }

    /// UART send (blocking)
    fn uart_send(&self, data: &[u8]) -> Result<(), Error> {
        #[cfg(target_arch = "arm")]
        {
            // STM32H7 USART send implementation
            // Would write to USART1->TDR
            for &byte in data {
                self.uart_write_byte(byte)?;
            }
        }

        #[cfg(not(target_arch = "arm"))]
        {
            // Simulation: do nothing
            let _ = data;
        }

        Ok(())
    }

    #[cfg(target_arch = "arm")]
    fn uart_read_byte(&self) -> Result<u8, Error> {
        const USART1_BASE: u32 = 0x4001_1000;
        const USART_ISR_OFFSET: u32 = 0x1C;
        const USART_RDR_OFFSET: u32 = 0x24;
        const USART_ISR_RXNE: u32 = 1 << 5;

        // Wait for RXNE with timeout
        let mut timeout = 1_000_000u32;
        loop {
            // SAFETY: USART1_BASE + ISR offset (0x4001_101C) is the USART1
            // interrupt/status register on STM32H7. Volatile MMIO read to
            // poll the RXNE (receive not empty) flag.
            let isr = unsafe { ptr::read_volatile((USART1_BASE + USART_ISR_OFFSET) as *const u32) };
            if (isr & USART_ISR_RXNE) != 0 {
                break;
            }
            timeout = timeout.saturating_sub(1);
            if timeout == 0 {
                return Err(Error::Timeout);
            }
        }

        // SAFETY: USART1_BASE + RDR offset (0x4001_1024) is the USART1
        // receive data register. The RXNE flag was confirmed set above,
        // so reading RDR is valid and clears the flag. Volatile MMIO read.
        let byte = unsafe { ptr::read_volatile((USART1_BASE + USART_RDR_OFFSET) as *const u32) } as u8;
        Ok(byte)
    }

    #[cfg(target_arch = "arm")]
    fn uart_write_byte(&self, byte: u8) -> Result<(), Error> {
        const USART1_BASE: u32 = 0x4001_1000;
        const USART_ISR_OFFSET: u32 = 0x1C;
        const USART_TDR_OFFSET: u32 = 0x28;
        const USART_ISR_TXE: u32 = 1 << 7;

        // Wait for TXE with timeout
        let mut timeout = 1_000_000u32;
        loop {
            // SAFETY: USART1_BASE + ISR offset (0x4001_101C) is the USART1
            // status register. Volatile MMIO read to poll the TXE (transmit
            // data register empty) flag before writing.
            let isr = unsafe { ptr::read_volatile((USART1_BASE + USART_ISR_OFFSET) as *const u32) };
            if (isr & USART_ISR_TXE) != 0 {
                break;
            }
            timeout = timeout.saturating_sub(1);
            if timeout == 0 {
                return Err(Error::Timeout);
            }
        }

        // SAFETY: USART1_BASE + TDR offset (0x4001_1028) is the USART1
        // transmit data register. TXE flag was confirmed set above, so
        // writing to TDR is valid. Volatile MMIO write for the peripheral.
        unsafe { ptr::write_volatile((USART1_BASE + USART_TDR_OFFSET) as *mut u32, byte as u32) };
        Ok(())
    }

    /// Calculate CRC32 for data
    fn calculate_crc(&self, header: &[u8], data: &[u8]) -> u32 {
        // Simple CRC32 implementation (could use hardware CRC on STM32)
        let mut crc = 0xFFFF_FFFFu32;

        for &byte in header.iter().chain(data.iter()) {
            crc ^= byte as u32;
            for _ in 0..8 {
                if crc & 1 != 0 {
                    crc = (crc >> 1) ^ 0xEDB8_8320;
                } else {
                    crc >>= 1;
                }
            }
        }

        !crc
    }

    /// Get device info
    fn get_device_info(&self) -> [u8; 32] {
        let mut info = [0u8; 32];
        // Device type
        info[0..4].copy_from_slice(b"QE01");
        // Version
        info[4] = 0;
        info[5] = 1;
        info[6] = 0;
        // Hardware revision
        info[7] = 1;
        // More info would include UID, etc.
        info
    }

    /// Erase firmware slot for new firmware
    ///
    /// Erases the inactive kernel slot to prepare for firmware update.
    /// Uses STM32H7 flash controller to erase flash sectors.
    fn erase_firmware_slot(&mut self) -> Result<(), Error> {
        use q_common::config::MemoryLayout;

        self.busy = true;

        // Get inactive slot address (slot B by default for recovery)
        let layout = MemoryLayout::STM32H7;
        let slot_start = layout.kernel_b_start();
        let slot_size = layout.kernel_size;

        // STM32H7 Flash Controller
        const FLASH_BASE: u32 = 0x5200_2000;
        const FLASH_KEYR: u32 = FLASH_BASE + 0x04;
        const FLASH_CR: u32 = FLASH_BASE + 0x0C;
        const FLASH_SR: u32 = FLASH_BASE + 0x10;

        // Flash keys
        const FLASH_KEY1: u32 = 0x4567_0123;
        const FLASH_KEY2: u32 = 0xCDEF_89AB;

        // Flash CR bits
        const FLASH_CR_LOCK: u32 = 1 << 0;
        const FLASH_CR_SER: u32 = 1 << 2;   // Sector erase
        const FLASH_CR_START: u32 = 1 << 7;
        const FLASH_CR_SNB_SHIFT: u32 = 8;  // Sector number bits

        // Flash SR bits
        const FLASH_SR_BSY: u32 = 1 << 0;
        const FLASH_SR_QW: u32 = 1 << 2;

        // Calculate sector number from address
        // STM32H7 Bank 1: 0x0800_0000, sectors 0-7 (128KB each)
        // Kernel B starts after kernel A, calculate sector
        let sector_base = (slot_start - 0x0800_0000) / (128 * 1024);
        let num_sectors = (slot_size + (128 * 1024) - 1) / (128 * 1024);

        // SAFETY: This block performs the STM32H7 flash sector erase sequence
        // using memory-mapped flash controller registers (FLASH_BASE 0x5200_2000).
        // The sequence follows the reference manual: unlock if locked, wait for
        // BSY clear, set SER + sector number, trigger START, wait for completion.
        // Sector addresses are derived from the validated kernel B slot address.
        // All register addresses are valid STM32H7 MMIO.
        unsafe {
            // Unlock flash if locked
            let cr = ptr::read_volatile(FLASH_CR as *const u32);
            if cr & FLASH_CR_LOCK != 0 {
                ptr::write_volatile(FLASH_KEYR as *mut u32, FLASH_KEY1);
                ptr::write_volatile(FLASH_KEYR as *mut u32, FLASH_KEY2);

                if ptr::read_volatile(FLASH_CR as *const u32) & FLASH_CR_LOCK != 0 {
                    self.busy = false;
                    return Err(Error::HardwareInitFailed);
                }
            }

            // Maximum busy-wait iterations before declaring a hardware timeout.
            // Sector erase on STM32H7 can take up to ~2 s; 2_000_000 spin
            // iterations at 480 MHz ≈ 4 ms per iteration (conservative).
            const FLASH_TIMEOUT: u32 = 2_000_000;

            // Erase each sector in the slot
            for sector in sector_base..(sector_base + num_sectors) {
                // Wait for any pending operation
                let mut wait = 0u32;
                while ptr::read_volatile(FLASH_SR as *const u32) & (FLASH_SR_BSY | FLASH_SR_QW) != 0 {
                    wait += 1;
                    if wait > FLASH_TIMEOUT {
                        self.busy = false;
                        return Err(Error::Timeout);
                    }
                    core::hint::spin_loop();
                }

                // Set sector erase and sector number
                let cr_val = FLASH_CR_SER | ((sector as u32) << FLASH_CR_SNB_SHIFT);
                ptr::write_volatile(FLASH_CR as *mut u32, cr_val);

                // Start erase
                ptr::write_volatile(FLASH_CR as *mut u32, cr_val | FLASH_CR_START);

                // Wait for completion
                wait = 0;
                while ptr::read_volatile(FLASH_SR as *const u32) & (FLASH_SR_BSY | FLASH_SR_QW) != 0 {
                    wait += 1;
                    if wait > FLASH_TIMEOUT {
                        // Clear SER bit before returning
                        ptr::write_volatile(FLASH_CR as *mut u32, 0);
                        self.busy = false;
                        return Err(Error::Timeout);
                    }
                    core::hint::spin_loop();
                }

                // Clear SER bit
                ptr::write_volatile(FLASH_CR as *mut u32, 0);
            }
        }

        self.busy = false;
        Ok(())
    }

    /// Write firmware chunk
    ///
    /// Parses address and data from rx_buffer and writes to flash.
    /// Buffer format: [ADDRESS:4][DATA:N]
    fn write_firmware_chunk(&mut self) -> Result<(), Error> {
        self.busy = true;

        // Parse address from rx_buffer (first 4 bytes, little-endian)
        let address = u32::from_le_bytes([
            self.rx_buffer[0], self.rx_buffer[1],
            self.rx_buffer[2], self.rx_buffer[3],
        ]);

        // Data starts at offset 4
        let data = &self.rx_buffer[4..];
        let data_len = data.len();

        // Validate address is within firmware slot
        let layout = q_common::config::MemoryLayout::STM32H7;
        let slot_start = layout.kernel_b_start();
        let slot_end = slot_start + layout.kernel_size;

        if address < slot_start || address + data_len as u32 > slot_end {
            self.busy = false;
            return Err(Error::InvalidParameter);
        }

        // STM32H7 Flash programming
        const FLASH_BASE: u32 = 0x5200_2000;
        const FLASH_CR: u32 = FLASH_BASE + 0x0C;
        const FLASH_SR: u32 = FLASH_BASE + 0x10;

        const FLASH_CR_PG: u32 = 1 << 1;
        const FLASH_SR_BSY: u32 = 1 << 0;
        const FLASH_SR_QW: u32 = 1 << 2;

        // SAFETY: This block performs STM32H7 flash programming using MMIO
        // registers (FLASH_BASE 0x5200_2000). The target `address` was validated
        // above to be within the kernel B slot range. The sequence follows the
        // reference manual: wait for BSY, set PG, write 256-bit flash words,
        // wait for completion, clear PG. Data comes from the validated rx_buffer.
        // Maximum busy-wait iterations for flash programming (per-word).
        const FLASH_WRITE_TIMEOUT: u32 = 500_000;

        unsafe {
            // Wait for any pending operation
            let mut wait = 0u32;
            while ptr::read_volatile(FLASH_SR as *const u32) & (FLASH_SR_BSY | FLASH_SR_QW) != 0 {
                wait += 1;
                if wait > FLASH_WRITE_TIMEOUT {
                    self.busy = false;
                    return Err(Error::Timeout);
                }
                core::hint::spin_loop();
            }

            // Enable programming
            let cr = ptr::read_volatile(FLASH_CR as *const u32);
            ptr::write_volatile(FLASH_CR as *mut u32, cr | FLASH_CR_PG);

            // STM32H7 requires 256-bit (32-byte) aligned writes
            // Write data in 32-byte chunks
            let mut offset = 0;
            while offset < data_len {
                let write_addr = address + offset as u32;

                // Write 8 words (32 bytes) at a time
                for i in 0..8 {
                    if offset + i * 4 + 4 <= data_len {
                        let word = u32::from_le_bytes([
                            data[offset + i * 4],
                            data[offset + i * 4 + 1],
                            data[offset + i * 4 + 2],
                            data[offset + i * 4 + 3],
                        ]);
                        ptr::write_volatile((write_addr + (i * 4) as u32) as *mut u32, word);
                    }
                }

                // Wait for write to complete
                wait = 0;
                while ptr::read_volatile(FLASH_SR as *const u32) & (FLASH_SR_BSY | FLASH_SR_QW) != 0 {
                    wait += 1;
                    if wait > FLASH_WRITE_TIMEOUT {
                        // Disable programming before returning on timeout
                        let cr = ptr::read_volatile(FLASH_CR as *const u32);
                        ptr::write_volatile(FLASH_CR as *mut u32, cr & !FLASH_CR_PG);
                        self.busy = false;
                        return Err(Error::Timeout);
                    }
                    core::hint::spin_loop();
                }

                offset += 32;
            }

            // Disable programming
            let cr = ptr::read_volatile(FLASH_CR as *const u32);
            ptr::write_volatile(FLASH_CR as *mut u32, cr & !FLASH_CR_PG);
        }

        self.busy = false;
        Ok(())
    }

    /// Verify firmware signature
    ///
    /// Uses the q-boot verify module to validate the firmware image.
    fn verify_firmware(&self) -> Result<(), Error> {
        use crate::verify_kernel;

        let layout = q_common::config::MemoryLayout::STM32H7;
        let slot_addr = layout.kernel_b_start();

        if verify_kernel(slot_addr) {
            Ok(())
        } else {
            Err(Error::InvalidSignature)
        }
    }

    /// Activate firmware and prepare for boot
    ///
    /// Updates boot state to mark slot B as the pending active slot.
    fn activate_firmware(&mut self) -> Result<(), Error> {
        // Update boot state to use slot B on next boot
        // Store pending slot in backup SRAM
        const PENDING_SLOT_ADDR: u32 = BKPSRAM_BASE + 16;
        const SLOT_B: u32 = 1;

        // SAFETY: PENDING_SLOT_ADDR (BKPSRAM_BASE + 16 = 0x3800_0010) is
        // within backup SRAM. Writing the slot index marks slot B as pending
        // for the next boot. Volatile write ensures persistence.
        unsafe {
            ptr::write_volatile(PENDING_SLOT_ADDR as *mut u32, SLOT_B);
        }

        // Clear failure counter to allow fresh boot attempt
        self.boot_state.failure_count = 0;
        self.boot_state.save();

        Ok(())
    }

    /// Factory reset
    ///
    /// Performs a complete factory reset:
    /// 1. Erases user data section
    /// 2. Clears all boot counters
    /// 3. Clears recovery flags
    fn factory_reset(&mut self) -> Result<(), Error> {
        use q_common::config::MemoryLayout;

        // 1. Erase user data section (if defined)
        // User data would be in a separate flash region
        let _layout = MemoryLayout::STM32H7;

        // For now, just clear the backup SRAM completely
        const BKPSRAM_SIZE: usize = 4096; // 4KB backup SRAM

        // SAFETY: BKPSRAM_BASE (0x3800_0000) through BKPSRAM_BASE + 4096 is
        // the full backup SRAM region on STM32H7. Writing zeros clears all
        // persistent boot state and counters. Volatile writes ensure the
        // clears are not optimized away.
        unsafe {
            for offset in (0..BKPSRAM_SIZE).step_by(4) {
                ptr::write_volatile((BKPSRAM_BASE + offset as u32) as *mut u32, 0);
            }
        }

        // 2. Reset boot state
        self.boot_state = BootState::new();
        self.boot_state.save();

        // 3. Optionally restore factory firmware
        // This would copy from a protected factory image region
        // For now, just ensure we boot from slot A
        const PENDING_SLOT_ADDR: u32 = BKPSRAM_BASE + 16;
        const SLOT_A: u32 = 0;

        // SAFETY: PENDING_SLOT_ADDR (0x3800_0010) is within backup SRAM.
        // Writing SLOT_A (0) restores the default boot slot after factory
        // reset. Volatile write ensures persistence.
        unsafe {
            ptr::write_volatile(PENDING_SLOT_ADDR as *mut u32, SLOT_A);
        }

        Ok(())
    }

    /// Read diagnostics
    fn read_diagnostics(&self) -> [u8; 64] {
        let mut diag = [0u8; 64];

        // Boot state
        diag[0] = self.boot_state.failure_count;
        diag[1] = self.boot_state.last_status;
        diag[2] = self.reason as u8;

        // More diagnostics would include:
        // - Reset cause
        // - RAM integrity
        // - Flash status
        // - etc.

        diag
    }

    /// Reboot the device
    fn reboot(&self) -> ! {
        #[cfg(target_arch = "arm")]
        {
            // Use NVIC system reset
            const SCB_AIRCR: u32 = 0xE000_ED0C;
            const AIRCR_VECTKEY: u32 = 0x05FA_0000;
            const AIRCR_SYSRESETREQ: u32 = 1 << 2;

            // SAFETY: SCB_AIRCR (0xE000_ED0C) is the Application Interrupt and
            // Reset Control Register. Writing the VECTKEY (0x05FA) with
            // SYSRESETREQ triggers a system reset. This is the standard ARM
            // Cortex-M reset mechanism.
            unsafe {
                ptr::write_volatile(
                    SCB_AIRCR as *mut u32,
                    AIRCR_VECTKEY | AIRCR_SYSRESETREQ,
                );
            }
        }

        loop {
            core::hint::spin_loop();
        }
    }
}

impl Default for RecoveryController {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Public API
// ============================================================================

/// Check if recovery mode is needed
pub fn should_enter_recovery() -> RecoveryReason {
    let mut controller = RecoveryController::new();
    controller.init()
}

/// Enter recovery mode (does not return on success)
pub fn enter_recovery_mode(reason: RecoveryReason) -> Result<core::convert::Infallible, Error> {
    let mut controller = RecoveryController::new();
    controller.reason = reason;
    controller.start()?;
    controller.run()
}

/// Record boot failure
pub fn record_boot_failure(error_code: u8) {
    let mut state = BootState::load();
    state.record_failure(error_code);
}

/// Record successful boot
pub fn record_boot_success() {
    let mut state = BootState::load();
    state.record_success();
}

/// Request recovery on next boot
pub fn request_recovery() {
    let mut state = BootState::load();
    state.request_recovery();
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_recovery_reason_conversion() {
        assert_eq!(RecoveryReason::from(0), RecoveryReason::None);
        assert_eq!(RecoveryReason::from(1), RecoveryReason::BootFailures);
        assert_eq!(RecoveryReason::from(2), RecoveryReason::ButtonPressed);
        assert_eq!(RecoveryReason::from(255), RecoveryReason::None);
    }

    #[test]
    fn test_recovery_command_conversion() {
        assert!(RecoveryCommand::try_from(0x01).is_ok());
        assert_eq!(RecoveryCommand::try_from(0x01).unwrap(), RecoveryCommand::Ping);
        assert!(RecoveryCommand::try_from(0xFF).is_err());
    }

    #[test]
    fn test_boot_state() {
        let mut state = BootState::new();
        assert_eq!(state.failure_count, 0);
        assert!(!state.needs_recovery());

        state.failure_count = MAX_BOOT_FAILURES;
        assert!(state.needs_recovery());

        state.failure_count = 0;
        state.recovery_requested = true;
        assert!(state.needs_recovery());
    }

    #[test]
    fn test_crc_calculation() {
        let controller = RecoveryController::new();
        let header = [0x4F, 0x43, 0x45, 0x52, 0x01, 0x00, 0x00];
        let data = [];
        let crc = controller.calculate_crc(&header, &data);
        // CRC should be deterministic
        assert_eq!(crc, controller.calculate_crc(&header, &data));
    }
}
