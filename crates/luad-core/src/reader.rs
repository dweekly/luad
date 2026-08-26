//! Memory-safe, bounds-checked binary reader with resource limit enforcement,
//! provenance tracking, and strict/permissive error collection.

use crate::diagnostic::{Diagnostic, DiagnosticCategory};
use crate::id::{ProtoPath, StableId};
use crate::limits::{ParseMode, ResourceLimits};
use crate::provenance::SourceLocation;

/// A bounds-checked cursor reading over input bytes.
pub struct SafeReader<'a> {
    data: &'a [u8],
    cursor: usize,
    base_offset: usize,
    limits: ResourceLimits,
    mode: ParseMode,
    current_proto_path: ProtoPath,
    total_prototypes: usize,
    diagnostics: Vec<Diagnostic>,
}

impl<'a> SafeReader<'a> {
    /// Create a new reader with default limits and strict mode.
    #[must_use]
    pub fn new(data: &'a [u8]) -> Self {
        Self::with_options(data, 0, ResourceLimits::default(), ParseMode::Strict)
    }

    /// Create a new reader with custom options.
    #[must_use]
    pub fn with_options(
        data: &'a [u8],
        base_offset: usize,
        limits: ResourceLimits,
        mode: ParseMode,
    ) -> Self {
        Self {
            data,
            cursor: 0,
            base_offset,
            limits,
            mode,
            current_proto_path: ProtoPath::root(),
            total_prototypes: 0,
            diagnostics: Vec::new(),
        }
    }

    /// Number of remaining bytes.
    #[must_use]
    pub fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.cursor)
    }

    /// Whether there are bytes remaining to be read.
    #[must_use]
    pub fn has_remaining(&self) -> bool {
        self.cursor < self.data.len()
    }

    /// Current absolute byte position.
    #[must_use]
    pub fn position(&self) -> usize {
        self.base_offset + self.cursor
    }

    /// Relative cursor offset from beginning of data slice.
    #[must_use]
    pub fn cursor_offset(&self) -> usize {
        self.cursor
    }

    /// Slice of the remaining unconsumed bytes.
    #[must_use]
    pub fn remaining_bytes(&self) -> &'a [u8] {
        if self.cursor <= self.data.len() {
            &self.data[self.cursor..]
        } else {
            &[]
        }
    }

    /// Slice of bytes between start_cursor and current cursor.
    pub fn slice_from_cursor(&self, start_cursor: usize) -> Result<&'a [u8], Diagnostic> {
        if start_cursor <= self.cursor && self.cursor <= self.data.len() {
            Ok(&self.data[start_cursor..self.cursor])
        } else {
            Err(Diagnostic::error(
                "CORE-SLICE-001",
                DiagnosticCategory::Parse,
                StableId::Chunk,
                "Invalid cursor range for slice",
            ))
        }
    }

    /// Complete raw data slice.
    #[must_use]
    pub fn raw_data(&self) -> &'a [u8] {
        self.data
    }

    /// Reader parse mode.
    #[must_use]
    pub fn mode(&self) -> ParseMode {
        self.mode
    }

    /// Get current prototype path.
    #[must_use]
    pub fn current_proto_path(&self) -> &ProtoPath {
        &self.current_proto_path
    }

    /// Access current resource limits.
    #[must_use]
    pub fn limits(&self) -> &ResourceLimits {
        &self.limits
    }

    /// Calculate safe vector pre-allocation capacity bounded by remaining input bytes.
    #[must_use]
    pub fn safe_capacity(&self, requested_count: usize, element_min_bytes: usize) -> usize {
        let max_possible = self
            .remaining()
            .checked_div(element_min_bytes)
            .unwrap_or_else(|| self.remaining());
        requested_count.min(max_possible).min(1024)
    }

    /// Total number of prototypes encountered so far.
    #[must_use]
    pub fn total_prototypes(&self) -> usize {
        self.total_prototypes
    }

    /// Access current collected diagnostics.
    #[must_use]
    pub fn diagnostics(&self) -> &[Diagnostic] {
        &self.diagnostics
    }

    /// Take diagnostics out of reader.
    pub fn take_diagnostics(&mut self) -> Vec<Diagnostic> {
        std::mem::take(&mut self.diagnostics)
    }

    /// Record a diagnostic.
    pub fn record_diagnostic(&mut self, diag: Diagnostic) -> Result<(), Diagnostic> {
        let is_error = diag.severity == crate::diagnostic::Severity::Error;
        if self.diagnostics.len() < self.limits.max_diagnostics {
            self.diagnostics.push(diag.clone());
        }
        if is_error && self.mode == ParseMode::Strict {
            Err(diag)
        } else {
            Ok(())
        }
    }

    /// Read exact number of bytes.
    pub fn read_exact(&mut self, len: usize) -> Result<&'a [u8], Diagnostic> {
        let start = self.cursor;
        let end = start.checked_add(len).ok_or_else(|| {
            Diagnostic::error(
                "CORE-OVERFLOW-001",
                DiagnosticCategory::Parse,
                StableId::Chunk,
                "Integer overflow calculating byte slice bounds",
            )
        })?;

        if end > self.data.len() {
            let diag = Diagnostic::error(
                "CORE-TRUNC-001",
                DiagnosticCategory::Parse,
                StableId::Proto(self.current_proto_path.clone()),
                format!(
                    "Unexpected EOF: requested {len} bytes at offset {}, only {} available",
                    self.base_offset + start,
                    self.data.len().saturating_sub(start)
                ),
            )
            .with_source(SourceLocation::new(
                self.base_offset + start,
                &self.data[start..],
            ));

            self.record_diagnostic(diag.clone())?;
            return Err(diag);
        }

        self.cursor = end;
        Ok(&self.data[start..end])
    }

    /// Read a single byte.
    pub fn read_u8(&mut self) -> Result<u8, Diagnostic> {
        let bytes = self.read_exact(1)?;
        Ok(bytes[0])
    }

    /// Read 2 bytes as little-endian u16.
    pub fn read_u16_le(&mut self) -> Result<u16, Diagnostic> {
        let bytes = self.read_exact(2)?;
        Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
    }

    /// Read 4 bytes as little-endian u32.
    pub fn read_u32_le(&mut self) -> Result<u32, Diagnostic> {
        let bytes = self.read_exact(4)?;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    /// Read 8 bytes as little-endian u64.
    pub fn read_u64_le(&mut self) -> Result<u64, Diagnostic> {
        let bytes = self.read_exact(8)?;
        Ok(u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }

    /// Read 4 bytes as little-endian i32.
    pub fn read_i32_le(&mut self) -> Result<i32, Diagnostic> {
        let bytes = self.read_exact(4)?;
        Ok(i32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    /// Read 8 bytes as little-endian i64.
    pub fn read_i64_le(&mut self) -> Result<i64, Diagnostic> {
        let bytes = self.read_exact(8)?;
        Ok(i64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }

    /// Read 8 bytes as little-endian f64.
    pub fn read_f64_le(&mut self) -> Result<f64, Diagnostic> {
        let bytes = self.read_exact(8)?;
        Ok(f64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }

    /// Read Lua 5.4 variable-length integer (`loadUnsigned` / MSB-first 7-bit chunks terminated by bit 7 set).
    pub fn read_varint_lua54(&mut self) -> Result<(u64, SourceLocation), Diagnostic> {
        let start_pos = self.position();
        let start_cursor = self.cursor;
        let mut value: u64 = 0;

        loop {
            let byte = self.read_u8()?;
            if value >= (u64::MAX >> 7) {
                let diag = Diagnostic::error(
                    "L54-VARINT-001",
                    DiagnosticCategory::Parse,
                    StableId::Proto(self.current_proto_path.clone()),
                    "Variable-length integer overflow",
                );
                self.record_diagnostic(diag.clone())?;
                return Err(diag);
            }

            value = (value << 7) | ((byte & 0x7F) as u64);

            if (byte & 0x80) != 0 {
                break;
            }
        }

        let raw_bytes = self.slice_from_cursor(start_cursor)?;
        let loc = SourceLocation::new(start_pos, raw_bytes);
        Ok((value, loc))
    }

    /// Read Lua 5.5 variable-length integer (MSB continuation bit: (b & 0x80) != 0 continues).
    pub fn read_varint_lua55(&mut self) -> Result<(u64, SourceLocation), Diagnostic> {
        let start_pos = self.position();
        let start_cursor = self.cursor;
        let mut value: u64 = 0;

        loop {
            let byte = self.read_u8()?;
            if value > (u64::MAX >> 7) {
                let diag = Diagnostic::error(
                    "L55-VARINT-001",
                    DiagnosticCategory::Parse,
                    StableId::Proto(self.current_proto_path.clone()),
                    "Variable-length integer overflow",
                );
                self.record_diagnostic(diag.clone())?;
                return Err(diag);
            }

            value = (value << 7) | ((byte & 0x7F) as u64);

            if (byte & 0x80) == 0 {
                break;
            }
        }

        let raw_bytes = self.slice_from_cursor(start_cursor)?;
        let loc = SourceLocation::new(start_pos, raw_bytes);
        Ok((value, loc))
    }

    /// Align reader position to a power-of-two byte boundary, consuming padding bytes.
    pub fn align_to(&mut self, align: usize) -> Result<(), Diagnostic> {
        let current_pos = self.position();
        let rem = current_pos % align;
        if rem != 0 {
            let padding = align - rem;
            let _ = self.read_exact(padding)?;
        }
        Ok(())
    }

    /// Enforce `max_string_bytes` before reading or retaining a string payload.
    pub fn check_string_limit<F>(
        &mut self,
        content_len: u64,
        make_diagnostic: F,
    ) -> Result<(), Diagnostic>
    where
        F: FnOnce(StableId, String) -> Diagnostic,
    {
        if content_len > self.limits.max_string_bytes as u64 {
            let diagnostic = make_diagnostic(
                StableId::Proto(self.current_proto_path.clone()),
                format!(
                    "String length {content_len} exceeds limit of {} bytes",
                    self.limits.max_string_bytes
                ),
            );
            self.record_diagnostic(diagnostic.clone())?;
            return Err(diagnostic);
        }
        Ok(())
    }

    /// Read a size_t encoded integer in Lua 5.4 (used for string length, table sizes, etc.).
    pub fn read_size_lua54(&mut self) -> Result<(usize, SourceLocation), Diagnostic> {
        let (val, loc) = self.read_varint_lua54()?;
        let usize_val = usize::try_from(val).map_err(|_| {
            Diagnostic::error(
                "L54-SIZE-001",
                DiagnosticCategory::Parse,
                StableId::Proto(self.current_proto_path.clone()),
                format!("Size {val} exceeds host pointer width"),
            )
        })?;
        Ok((usize_val, loc))
    }

    /// Read a Lua 5.4 string with bounds and size limits.
    pub fn read_string_lua54(&mut self) -> Result<(Option<Vec<u8>>, SourceLocation), Diagnostic> {
        let start_pos = self.position();
        let start_cursor = self.cursor;
        let (size, _) = self.read_size_lua54()?;

        if size == 0 {
            // In Lua 5.4, size 0 denotes a NULL string.
            let raw_bytes = &self.data[start_cursor..self.cursor];
            return Ok((None, SourceLocation::new(start_pos, raw_bytes)));
        }

        let content_len = size.saturating_sub(1);
        self.check_string_limit(content_len as u64, |target, message| {
            Diagnostic::error("L54-STR-001", DiagnosticCategory::Parse, target, message)
        })?;

        let content = self.read_exact(content_len)?;
        let raw_bytes = &self.data[start_cursor..self.cursor];
        Ok((
            Some(content.to_vec()),
            SourceLocation::new(start_pos, raw_bytes),
        ))
    }

    /// Enter a child prototype context, enforcing depth and prototype count limits.
    pub fn enter_proto(
        &mut self,
        child_index: usize,
    ) -> Result<ProtoPathGuard<'a, '_>, Diagnostic> {
        let child_path = self.current_proto_path.child(child_index);
        let depth = child_path.depth();

        if depth > self.limits.max_nesting_depth {
            let diag = Diagnostic::error(
                "CORE-LIMIT-001",
                DiagnosticCategory::Parse,
                StableId::Proto(child_path.clone()),
                format!(
                    "Prototype nesting depth {depth} exceeds configured limit of {}",
                    self.limits.max_nesting_depth
                ),
            );
            self.record_diagnostic(diag.clone())?;
            return Err(diag);
        }

        self.total_prototypes += 1;
        if self.total_prototypes > self.limits.max_total_prototypes {
            let diag = Diagnostic::error(
                "CORE-LIMIT-002",
                DiagnosticCategory::Parse,
                StableId::Proto(child_path.clone()),
                format!(
                    "Total prototype count {} exceeds configured limit of {}",
                    self.total_prototypes, self.limits.max_total_prototypes
                ),
            );
            self.record_diagnostic(diag.clone())?;
            return Err(diag);
        }

        let old_path = std::mem::replace(&mut self.current_proto_path, child_path);
        Ok(ProtoPathGuard {
            reader: self,
            previous_path: old_path,
        })
    }
}

/// RAII guard that restores parent prototype path on drop.
pub struct ProtoPathGuard<'a, 'r> {
    reader: &'r mut SafeReader<'a>,
    previous_path: ProtoPath,
}

impl<'a, 'r> Drop for ProtoPathGuard<'a, 'r> {
    fn drop(&mut self) {
        self.reader.current_proto_path =
            std::mem::replace(&mut self.previous_path, ProtoPath::root());
    }
}

impl<'a, 'r> std::ops::Deref for ProtoPathGuard<'a, 'r> {
    type Target = SafeReader<'a>;

    fn deref(&self) -> &Self::Target {
        self.reader
    }
}

impl<'a, 'r> std::ops::DerefMut for ProtoPathGuard<'a, 'r> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.reader
    }
}
