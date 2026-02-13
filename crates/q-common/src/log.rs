// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Qbitel Inc.

//! Logging infrastructure for Qbitel EdgeOS
//!
//! This module provides a lightweight, no_std compatible logging system.
//! Logs are written to a circular buffer and can be retrieved for debugging.
//!
//! # Security
//!
//! - Sensitive data (keys, passwords) must NEVER be logged
//! - Log levels control what is output in production vs development

use core::fmt::{self, Write};
use heapless::String;

/// Maximum log message length
pub const MAX_LOG_MESSAGE_LEN: usize = 128;

/// Log buffer size (number of entries)
pub const LOG_BUFFER_SIZE: usize = 32;

/// Log level enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum LogLevel {
    /// Errors that require immediate attention
    Error = 0,
    /// Warnings about potential issues
    Warn = 1,
    /// Informational messages
    Info = 2,
    /// Debug messages (development only)
    Debug = 3,
    /// Trace messages (very verbose, development only)
    Trace = 4,
}

impl LogLevel {
    /// Get the log level name
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Error => "ERROR",
            Self::Warn => "WARN",
            Self::Info => "INFO",
            Self::Debug => "DEBUG",
            Self::Trace => "TRACE",
        }
    }

    /// Get a short prefix for the log level
    #[must_use]
    pub const fn prefix(&self) -> char {
        match self {
            Self::Error => 'E',
            Self::Warn => 'W',
            Self::Info => 'I',
            Self::Debug => 'D',
            Self::Trace => 'T',
        }
    }
}

impl fmt::Display for LogLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Log entry structure
#[derive(Clone)]
pub struct LogEntry {
    /// Log level
    pub level: LogLevel,
    /// Timestamp (system ticks or Unix seconds)
    pub timestamp: u32,
    /// Module/component name
    pub module: &'static str,
    /// Log message
    pub message: String<MAX_LOG_MESSAGE_LEN>,
}

impl LogEntry {
    /// Create a new log entry
    #[must_use]
    pub fn new(level: LogLevel, timestamp: u32, module: &'static str, message: &str) -> Self {
        let mut msg = String::new();
        // Truncate if too long
        let _ = msg.push_str(&message[..message.len().min(MAX_LOG_MESSAGE_LEN)]);

        Self {
            level,
            timestamp,
            module,
            message: msg,
        }
    }
}

impl fmt::Debug for LogEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{:08X}] {} [{}] {}",
            self.timestamp,
            self.level.prefix(),
            self.module,
            self.message
        )
    }
}

impl fmt::Display for LogEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{:08X}] {} [{}] {}",
            self.timestamp,
            self.level.prefix(),
            self.module,
            self.message
        )
    }
}

/// Circular log buffer
pub struct LogBuffer {
    entries: [Option<LogEntry>; LOG_BUFFER_SIZE],
    write_index: usize,
    count: usize,
    min_level: LogLevel,
}

impl LogBuffer {
    /// Create a new empty log buffer
    #[must_use]
    pub const fn new() -> Self {
        const NONE: Option<LogEntry> = None;
        Self {
            entries: [NONE; LOG_BUFFER_SIZE],
            write_index: 0,
            count: 0,
            min_level: LogLevel::Info,
        }
    }

    /// Set the minimum log level
    pub fn set_min_level(&mut self, level: LogLevel) {
        self.min_level = level;
    }

    /// Get the minimum log level
    #[must_use]
    pub const fn min_level(&self) -> LogLevel {
        self.min_level
    }

    /// Check if a log level should be recorded
    #[must_use]
    pub const fn should_log(&self, level: LogLevel) -> bool {
        (level as u8) <= (self.min_level as u8)
    }

    /// Write a log entry
    pub fn write(&mut self, entry: LogEntry) {
        if !self.should_log(entry.level) {
            return;
        }

        self.entries[self.write_index] = Some(entry);
        self.write_index = (self.write_index + 1) % LOG_BUFFER_SIZE;
        if self.count < LOG_BUFFER_SIZE {
            self.count += 1;
        }
    }

    /// Log with format arguments
    pub fn log(&mut self, level: LogLevel, timestamp: u32, module: &'static str, args: fmt::Arguments<'_>) {
        if !self.should_log(level) {
            return;
        }

        let mut message = String::<MAX_LOG_MESSAGE_LEN>::new();
        let _ = message.write_fmt(args);

        self.write(LogEntry {
            level,
            timestamp,
            module,
            message,
        });
    }

    /// Get the number of entries
    #[must_use]
    pub const fn len(&self) -> usize {
        self.count
    }

    /// Check if buffer is empty
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Clear all entries
    pub fn clear(&mut self) {
        for entry in &mut self.entries {
            *entry = None;
        }
        self.write_index = 0;
        self.count = 0;
    }

    /// Iterate over entries (oldest first)
    pub fn iter(&self) -> LogBufferIter<'_> {
        LogBufferIter {
            buffer: self,
            index: 0,
            remaining: self.count,
        }
    }
}

impl Default for LogBuffer {
    fn default() -> Self {
        Self::new()
    }
}

/// Iterator over log buffer entries
pub struct LogBufferIter<'a> {
    buffer: &'a LogBuffer,
    index: usize,
    remaining: usize,
}

impl<'a> Iterator for LogBufferIter<'a> {
    type Item = &'a LogEntry;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }

        let start_index = if self.buffer.count < LOG_BUFFER_SIZE {
            0
        } else {
            self.buffer.write_index
        };

        let actual_index = (start_index + self.index) % LOG_BUFFER_SIZE;
        self.index += 1;
        self.remaining -= 1;

        self.buffer.entries[actual_index].as_ref()
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining, Some(self.remaining))
    }
}

/// Global log macros
#[macro_export]
macro_rules! log_error {
    ($buffer:expr, $ts:expr, $module:expr, $($arg:tt)*) => {
        $buffer.log($crate::log::LogLevel::Error, $ts, $module, format_args!($($arg)*))
    };
}

/// Log a warning message
#[macro_export]
macro_rules! log_warn {
    ($buffer:expr, $ts:expr, $module:expr, $($arg:tt)*) => {
        $buffer.log($crate::log::LogLevel::Warn, $ts, $module, format_args!($($arg)*))
    };
}

/// Log an informational message
#[macro_export]
macro_rules! log_info {
    ($buffer:expr, $ts:expr, $module:expr, $($arg:tt)*) => {
        $buffer.log($crate::log::LogLevel::Info, $ts, $module, format_args!($($arg)*))
    };
}

/// Log a debug message
#[macro_export]
macro_rules! log_debug {
    ($buffer:expr, $ts:expr, $module:expr, $($arg:tt)*) => {
        $buffer.log($crate::log::LogLevel::Debug, $ts, $module, format_args!($($arg)*))
    };
}

/// Log a trace-level message
#[macro_export]
macro_rules! log_trace {
    ($buffer:expr, $ts:expr, $module:expr, $($arg:tt)*) => {
        $buffer.log($crate::log::LogLevel::Trace, $ts, $module, format_args!($($arg)*))
    };
}
