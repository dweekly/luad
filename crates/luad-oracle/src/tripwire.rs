//! Hostile-input containment tripwire monitoring harness.
//!
//! Enforces numeric ceilings on child process execution:
//! 1. Wall-clock duration (`max_wall_time`)
//! 2. Peak resident set size (`max_peak_rss_bytes`)
//! 3. Standard output length (`max_stdout_bytes`)
//! 4. Standard error length (`max_stderr_bytes`)
//!
//! Provides negative controls to prove that the monitor detects over-budget executions.

use std::io::Write;
use std::path::Path;
use std::process::{Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};
use thiserror::Error;

/// Configurable resource budget for child process containment.
#[derive(Debug, Clone)]
pub struct TripwireBudget {
    /// Maximum allowed wall-clock duration.
    pub max_wall_time: Duration,
    /// Maximum allowed peak RSS in bytes.
    pub max_peak_rss_bytes: u64,
    /// Maximum allowed standard output length in bytes.
    pub max_stdout_bytes: usize,
    /// Maximum allowed standard error length in bytes.
    pub max_stderr_bytes: usize,
}

impl Default for TripwireBudget {
    fn default() -> Self {
        Self {
            // Default 3.0s wall-clock limit accommodates debug builds on shared CI workers.
            max_wall_time: Duration::from_millis(3000),
            // Default 64 MiB peak RSS accommodates debug binary loader + runtime overhead.
            max_peak_rss_bytes: 64 * 1024 * 1024,
            // Default 1 MiB output ceiling.
            max_stdout_bytes: 1024 * 1024,
            // Default 512 KiB error ceiling.
            max_stderr_bytes: 512 * 1024,
        }
    }
}

/// Recorded execution metrics from a monitored subprocess.
#[derive(Debug, Clone)]
pub struct TripwireMetrics {
    /// Subprocess exit status.
    pub status: ExitStatus,
    /// Standard output bytes captured from child.
    pub stdout: Vec<u8>,
    /// Cleaned standard error bytes captured from child (resource measurement trailer stripped).
    pub stderr: Vec<u8>,
    /// Measured wall-clock duration of child process execution.
    pub wall_time: Duration,
    /// Measured peak RSS in bytes, if available from system monitor.
    pub peak_rss_bytes: Option<u64>,
}

/// Error returned when an execution breaches its resource budget or fails to spawn.
#[derive(Debug, Error)]
pub enum TripwireError {
    #[error("Wall-clock time {elapsed:?} exceeded tripwire ceiling {ceiling:?}")]
    WallTimeCeilingExceeded {
        elapsed: Duration,
        ceiling: Duration,
    },

    #[error("Peak RSS {peak_rss_bytes} bytes exceeded tripwire ceiling {ceiling} bytes")]
    PeakMemoryCeilingExceeded { peak_rss_bytes: u64, ceiling: u64 },

    #[error("Standard output length {length} bytes exceeded tripwire ceiling {ceiling} bytes")]
    StdoutCeilingExceeded { length: usize, ceiling: usize },

    #[error("Standard error length {length} bytes exceeded tripwire ceiling {ceiling} bytes")]
    StderrCeilingExceeded { length: usize, ceiling: usize },

    #[error("Process execution error: {0}")]
    IoError(#[from] std::io::Error),
}

/// Parse macOS `/usr/bin/time -l` trailer to extract maximum resident set size in bytes
/// and strip the resource statistics from stderr.
pub fn parse_macos_time_trailer(raw_stderr: &[u8]) -> (Vec<u8>, Option<u64>) {
    let stderr_str = String::from_utf8_lossy(raw_stderr);
    let mut real_stderr_lines = Vec::new();
    let mut peak_rss = None;
    let mut in_time_trailer = false;

    for line in stderr_str.lines() {
        let trimmed = line.trim();
        if !in_time_trailer
            && trimmed.contains("real")
            && trimmed.contains("user")
            && trimmed.contains("sys")
        {
            in_time_trailer = true;
            continue;
        }

        if in_time_trailer {
            if trimmed.contains("maximum resident set size") {
                let parts: Vec<&str> = trimmed.split_whitespace().collect();
                if let Some(num_str) = parts.first() {
                    if let Ok(num) = num_str.parse::<u64>() {
                        peak_rss = Some(num);
                    }
                }
            }
            continue;
        }

        real_stderr_lines.push(line);
    }

    let cleaned_stderr = if in_time_trailer {
        let mut s = real_stderr_lines.join("\n");
        if !s.is_empty() && raw_stderr.ends_with(b"\n") {
            s.push('\n');
        }
        s.into_bytes()
    } else {
        raw_stderr.to_vec()
    };

    (cleaned_stderr, peak_rss)
}

/// Parse GNU `/usr/bin/time -v` trailer to extract maximum resident set size in bytes
/// and strip the resource statistics from stderr.
pub fn parse_gnu_time_trailer(raw_stderr: &[u8]) -> (Vec<u8>, Option<u64>) {
    let stderr_str = String::from_utf8_lossy(raw_stderr);
    let mut real_stderr_lines = Vec::new();
    let mut peak_rss = None;
    let mut in_time_trailer = false;

    for line in stderr_str.lines() {
        let trimmed = line.trim();
        if !in_time_trailer && trimmed.starts_with("Command being timed:") {
            in_time_trailer = true;
            continue;
        }

        if in_time_trailer {
            if trimmed.contains("Maximum resident set size (kbytes):") {
                if let Some(num_str) = trimmed.split(':').nth(1) {
                    if let Ok(num) = num_str.trim().parse::<u64>() {
                        // GNU time reports in kbytes
                        peak_rss = Some(num * 1024);
                    }
                }
            }
            continue;
        }

        real_stderr_lines.push(line);
    }

    let cleaned_stderr = if in_time_trailer {
        let mut s = real_stderr_lines.join("\n");
        if !s.is_empty() && raw_stderr.ends_with(b"\n") {
            s.push('\n');
        }
        s.into_bytes()
    } else {
        raw_stderr.to_vec()
    };

    (cleaned_stderr, peak_rss)
}

/// Execute a subprocess under tripwire resource monitoring.
pub fn run_with_tripwire(
    program: &Path,
    args: &[&str],
    stdin_data: Option<&[u8]>,
    budget: &TripwireBudget,
) -> Result<TripwireMetrics, TripwireError> {
    let time_bin = Path::new("/usr/bin/time");
    let has_time = time_bin.exists();

    #[cfg(target_os = "macos")]
    let use_macos_time = has_time;
    #[cfg(not(target_os = "macos"))]
    let use_macos_time = false;

    #[cfg(target_os = "linux")]
    let use_gnu_time = has_time;
    #[cfg(not(target_os = "linux"))]
    let use_gnu_time = false;

    let mut cmd = if use_macos_time {
        let mut c = Command::new("/usr/bin/time");
        c.arg("-l").arg(program);
        c.args(args);
        c
    } else if use_gnu_time {
        let mut c = Command::new("/usr/bin/time");
        c.arg("-v").arg(program);
        c.args(args);
        c
    } else {
        let mut c = Command::new(program);
        c.args(args);
        c
    };

    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());
    if stdin_data.is_some() {
        cmd.stdin(Stdio::piped());
    } else {
        cmd.stdin(Stdio::null());
    }

    let start = Instant::now();
    let mut child = cmd.spawn()?;

    if let Some(data) = stdin_data {
        if let Some(mut stdin) = child.stdin.take() {
            let _ = stdin.write_all(data);
        }
    }

    let output = child.wait_with_output()?;
    let wall_time = start.elapsed();

    let (cleaned_stderr, peak_rss_bytes) = if use_macos_time {
        parse_macos_time_trailer(&output.stderr)
    } else if use_gnu_time {
        parse_gnu_time_trailer(&output.stderr)
    } else {
        (output.stderr, None)
    };

    // 1. Verify wall time ceiling
    if wall_time > budget.max_wall_time {
        return Err(TripwireError::WallTimeCeilingExceeded {
            elapsed: wall_time,
            ceiling: budget.max_wall_time,
        });
    }

    // 2. Verify stdout length ceiling
    if output.stdout.len() > budget.max_stdout_bytes {
        return Err(TripwireError::StdoutCeilingExceeded {
            length: output.stdout.len(),
            ceiling: budget.max_stdout_bytes,
        });
    }

    // 3. Verify stderr length ceiling
    if cleaned_stderr.len() > budget.max_stderr_bytes {
        return Err(TripwireError::StderrCeilingExceeded {
            length: cleaned_stderr.len(),
            ceiling: budget.max_stderr_bytes,
        });
    }

    // 4. Verify peak memory ceiling (if measured)
    if let Some(rss) = peak_rss_bytes {
        if rss > budget.max_peak_rss_bytes {
            return Err(TripwireError::PeakMemoryCeilingExceeded {
                peak_rss_bytes: rss,
                ceiling: budget.max_peak_rss_bytes,
            });
        }
    }

    Ok(TripwireMetrics {
        status: output.status,
        stdout: output.stdout,
        stderr: cleaned_stderr,
        wall_time,
        peak_rss_bytes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_macos_time_trailer() {
        let raw = b"error message line 1\nerror message line 2\n        0.05 real         0.02 user         0.01 sys\n             3883008  maximum resident set size\n                   0  average shared memory size\n";
        let (cleaned, rss) = parse_macos_time_trailer(raw);
        assert_eq!(
            String::from_utf8_lossy(&cleaned),
            "error message line 1\nerror message line 2\n"
        );
        assert_eq!(rss, Some(3883008));
    }

    #[test]
    fn test_parse_gnu_time_trailer() {
        let raw = b"actual error line\n\tCommand being timed: \"luad inspect\"\n\tMaximum resident set size (kbytes): 4096\n";
        let (cleaned, rss) = parse_gnu_time_trailer(raw);
        assert_eq!(String::from_utf8_lossy(&cleaned), "actual error line\n");
        assert_eq!(rss, Some(4096 * 1024));
    }
}
