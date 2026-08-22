//! CLI exit code taxonomy adhering to PRD 6.6 contract.

/// Stable CLI process exit codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
#[allow(dead_code)]
pub enum ExitCode {
    /// Command completed and requested validity condition passed.
    Success = 0,
    /// Command completed but validation found invalid input.
    InvalidInput = 1,
    /// CLI usage or argument error.
    UsageError = 2,
    /// Input/output error (file read failure, permission, etc.).
    IoError = 3,
    /// Unsupported or ambiguous format without sufficient override.
    UnsupportedFormat = 4,
    /// Configured safety or resource limit reached.
    LimitExceeded = 5,
    /// Internal error / unhandled bug.
    InternalError = 6,
}

impl ExitCode {
    /// Exit current process with this code.
    pub fn exit(self) -> ! {
        std::process::exit(self as i32);
    }
}
