//! Incremental framing for command lines and message bodies.
//!
//! Both readers take arbitrary byte chunks, because that is what a socket
//! hands you: a command may arrive split across three reads, and the
//! end-of-data marker may straddle a chunk boundary. Neither reader performs
//! I/O, so every boundary case is reachable from a unit test — which is the
//! point, since the boundary cases are where the bugs are.
//!
//! # How much copying actually happens
//!
//! Command parsing is genuinely zero-copy: [`crate::command::parse`] returns
//! subslices of the caller's buffer. [`LineReader::take_line`] fills a buffer
//! the caller owns and reuses, so framing is allocation-free after the first
//! line.
//!
//! The body is copied exactly once, and that copy cannot be removed. Removing
//! dot-stuffing deletes bytes from the stream, so the output is not a subslice
//! of the input and cannot alias it. What matters is that it happens once:
//! after this, the body becomes `Bytes` and fanning it out to N destinations
//! costs N refcount bumps.
//!
//! # A limit worth fixing before production
//!
//! [`DataReader`] currently accumulates into memory. At the default 50 MB
//! ceiling that is 50 MB per concurrent connection, which is a denial of
//! service rather than a performance question — a few dozen slow senders can
//! exhaust the host without sending anything malformed.
//!
//! The fix belongs in Milestone 3, where the spool arrives: the reader should
//! write through to the spool file as bytes arrive rather than buffering, so
//! peak memory is one chunk regardless of message size. The state machine here
//! does not change — only where `push` sends its output.

/// Why a command line could not be framed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LineError {
    /// The line exceeded the configured limit. The reader resynchronises by
    /// discarding everything up to the next newline, so the connection can
    /// continue rather than being torn down.
    TooLong,
}

/// Frames CRLF-delimited command lines out of a byte stream.
#[derive(Debug)]
pub struct LineReader {
    buf: Vec<u8>,
    max: usize,
    /// Set after an overlong line: bytes are dropped until the next newline.
    discarding: bool,
}

impl LineReader {
    pub fn new(max: usize) -> Self {
        Self {
            buf: Vec::with_capacity(256),
            max,
            discarding: false,
        }
    }

    /// Add bytes read from the socket.
    pub fn feed(&mut self, chunk: &[u8]) {
        self.buf.extend_from_slice(chunk);
    }

    /// Bytes currently held but not yet forming a complete line.
    #[inline]
    pub fn buffered(&self) -> usize {
        self.buf.len()
    }

    /// Remove and return everything buffered.
    ///
    /// Needed when a `DATA` command is accepted: a pipelining client may have
    /// already sent part of the body in the same packet, and those bytes are
    /// sitting here rather than on the socket. Handing them to the body reader
    /// is the difference between working with pipelining clients and hanging
    /// on them.
    pub fn take_remaining(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.buf)
    }

    /// Take the next complete line into `out`, reusing its allocation.
    ///
    /// Returns `Ok(false)` when more bytes are needed. The line terminator is
    /// included, since the command parser strips it and accepts either form.
    pub fn take_line(&mut self, out: &mut Vec<u8>) -> Result<bool, LineError> {
        if self.discarding {
            match memchr(b'\n', &self.buf) {
                Some(i) => {
                    // Tail of the overlong line found; drop it and carry on.
                    self.buf.drain(..=i);
                    self.discarding = false;
                }
                None => {
                    // Still inside it. Drop what we have so the discard buffer
                    // cannot grow while waiting for the end.
                    self.buf.clear();
                    return Ok(false);
                }
            }
        }

        match memchr(b'\n', &self.buf) {
            Some(i) => {
                if i + 1 > self.max {
                    self.buf.drain(..=i);
                    return Err(LineError::TooLong);
                }
                out.clear();
                out.extend_from_slice(&self.buf[..=i]);
                self.buf.drain(..=i);
                Ok(true)
            }
            None => {
                if self.buf.len() > self.max {
                    // Already too long and its end has not arrived. Report now
                    // rather than buffering without bound, then swallow the
                    // remainder on subsequent calls.
                    self.buf.clear();
                    self.discarding = true;
                    return Err(LineError::TooLong);
                }
                Ok(false)
            }
        }
    }
}

/// Progress of a message body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataStatus {
    /// Terminator not yet seen.
    NeedMore,
    /// Terminator seen; the body is complete.
    Complete,
    /// The body exceeded the limit. Scanning continued to the terminator so
    /// the connection stays in sync and can be answered with 552 rather than
    /// dropped.
    TooLarge,
}

/// Where the terminator scan is, between chunks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Scan {
    /// At the start of a line.
    LineStart,
    /// At line start, having seen `.` — either stuffing or the terminator.
    Dot,
    /// At line start, having seen `.\r`.
    DotCr,
    /// Within a line.
    InLine,
    /// Within a line, having seen `\r`.
    InLineCr,
}

/// Reads a message body until `CRLF.CRLF`, removing dot-stuffing.
///
/// Both jobs have to happen in the same pass. A line consisting of a single
/// `.` ends the message, so a body line that genuinely begins with `.` is sent
/// with an extra one prepended, and the receiver removes it. Miss that and
/// bodies are silently corrupted; miss the terminator split across a chunk
/// boundary and the message never ends.
#[derive(Debug)]
pub struct DataReader {
    body: Vec<u8>,
    scan: Scan,
    max: usize,
    overflow: bool,
    complete: bool,
}

impl DataReader {
    pub fn new(max: usize) -> Self {
        Self {
            body: Vec::with_capacity(8 * 1024),
            // A body starts at the beginning of a line, so `.\r\n` as the very
            // first thing sent is a valid empty message.
            scan: Scan::LineStart,
            max,
            overflow: false,
            complete: false,
        }
    }

    /// Consume bytes from a chunk.
    ///
    /// Returns how many bytes were used. Anything left over followed the
    /// terminator and belongs to the next command, which matters when a client
    /// pipelines.
    pub fn feed(&mut self, chunk: &[u8]) -> (usize, DataStatus) {
        if self.complete {
            return (0, self.status());
        }

        for (i, &b) in chunk.iter().enumerate() {
            match self.scan {
                Scan::LineStart => match b {
                    b'.' => self.scan = Scan::Dot,
                    b'\r' => self.scan = Scan::InLineCr,
                    _ => {
                        self.push(b);
                        self.scan = Scan::InLine;
                    }
                },
                Scan::Dot => match b {
                    b'\r' => self.scan = Scan::DotCr,
                    _ => {
                        // Not the terminator, so the leading dot was stuffing
                        // and has already been dropped by not emitting it.
                        self.push(b);
                        self.scan = Scan::InLine;
                    }
                },
                Scan::DotCr => match b {
                    b'\n' => {
                        self.complete = true;
                        return (i + 1, self.status());
                    }
                    _ => {
                        // A bare CR after a leading dot: malformed, but keep
                        // the bytes rather than inventing a truncation.
                        self.push(b'\r');
                        if b == b'\r' {
                            self.scan = Scan::InLineCr;
                        } else {
                            self.push(b);
                            self.scan = Scan::InLine;
                        }
                    }
                },
                Scan::InLine => match b {
                    b'\r' => self.scan = Scan::InLineCr,
                    _ => self.push(b),
                },
                Scan::InLineCr => match b {
                    b'\n' => {
                        self.push(b'\r');
                        self.push(b'\n');
                        self.scan = Scan::LineStart;
                    }
                    b'\r' => {
                        self.push(b'\r');
                        // Still awaiting the LF of a possible CRLF.
                    }
                    _ => {
                        self.push(b'\r');
                        self.push(b);
                        self.scan = Scan::InLine;
                    }
                },
            }
        }

        (chunk.len(), self.status())
    }

    fn push(&mut self, b: u8) {
        // Past the limit the bytes are dropped but scanning continues, so the
        // terminator is still found and the session can be answered properly.
        if self.body.len() < self.max {
            self.body.push(b);
        } else {
            self.overflow = true;
        }
    }

    fn status(&self) -> DataStatus {
        if self.overflow {
            DataStatus::TooLarge
        } else if self.complete {
            DataStatus::Complete
        } else {
            DataStatus::NeedMore
        }
    }

    /// The body received so far, dot-unstuffed.
    #[inline]
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.body.len()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.body.is_empty()
    }

    /// Whether the terminator has been seen.
    #[inline]
    pub fn is_complete(&self) -> bool {
        self.complete
    }

    /// Whether the body exceeded the configured limit.
    ///
    /// Remains meaningful after completion, which is the point: the terminator
    /// is still found so the connection stays in sync, and the caller answers
    /// 552 rather than dropping the socket.
    #[inline]
    pub fn is_too_large(&self) -> bool {
        self.overflow
    }

    /// Take ownership of the body.
    pub fn into_body(self) -> Vec<u8> {
        self.body
    }
}

/// First index of `needle` in `haystack`.
///
/// Kept local so this module stays dependency free; swap for the `memchr`
/// crate if profiling ever says it matters.
fn memchr(needle: u8, haystack: &[u8]) -> Option<usize> {
    haystack.iter().position(|&b| b == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- LineReader ----

    fn lines(reader: &mut LineReader) -> Vec<String> {
        let mut out = Vec::new();
        let mut buf = Vec::new();
        while let Ok(true) = reader.take_line(&mut buf) {
            out.push(String::from_utf8_lossy(&buf).into_owned());
        }
        out
    }

    #[test]
    fn frames_one_line() {
        let mut r = LineReader::new(512);
        r.feed(b"EHLO host\r\n");
        assert_eq!(lines(&mut r), vec!["EHLO host\r\n"]);
    }

    #[test]
    fn frames_several_lines_from_one_chunk() {
        let mut r = LineReader::new(512);
        r.feed(b"EHLO host\r\nNOOP\r\nQUIT\r\n");
        assert_eq!(lines(&mut r), vec!["EHLO host\r\n", "NOOP\r\n", "QUIT\r\n"]);
    }

    #[test]
    fn reassembles_a_line_split_across_chunks() {
        let mut r = LineReader::new(512);
        let mut buf = Vec::new();
        r.feed(b"EH");
        assert_eq!(r.take_line(&mut buf), Ok(false));
        r.feed(b"LO ho");
        assert_eq!(r.take_line(&mut buf), Ok(false));
        r.feed(b"st\r\n");
        assert_eq!(r.take_line(&mut buf), Ok(true));
        assert_eq!(buf, b"EHLO host\r\n");
    }

    #[test]
    fn crlf_split_across_chunks() {
        let mut r = LineReader::new(512);
        let mut buf = Vec::new();
        r.feed(b"NOOP\r");
        assert_eq!(r.take_line(&mut buf), Ok(false));
        r.feed(b"\n");
        assert_eq!(r.take_line(&mut buf), Ok(true));
        assert_eq!(buf, b"NOOP\r\n");
    }

    #[test]
    fn accepts_bare_lf() {
        let mut r = LineReader::new(512);
        r.feed(b"NOOP\n");
        assert_eq!(lines(&mut r), vec!["NOOP\n"]);
    }

    #[test]
    fn overlong_line_reports_once_then_resyncs() {
        let mut r = LineReader::new(16);
        let mut buf = Vec::new();
        r.feed(b"AAAAAAAAAAAAAAAAAAAAAAAAAAAA");
        assert_eq!(r.take_line(&mut buf), Err(LineError::TooLong));
        // The rest of the overlong line is swallowed, not mistaken for a command.
        r.feed(b"AAAAAA\r\nNOOP\r\n");
        assert_eq!(r.take_line(&mut buf), Ok(true));
        assert_eq!(buf, b"NOOP\r\n");
    }

    #[test]
    fn overlong_buffer_does_not_grow_without_bound() {
        let mut r = LineReader::new(16);
        let mut buf = Vec::new();
        for _ in 0..100 {
            r.feed(&[b'A'; 64]);
            let _ = r.take_line(&mut buf);
        }
        assert!(r.buffered() <= 64, "buffered {} bytes", r.buffered());
    }

    #[test]
    fn take_line_reuses_the_caller_buffer() {
        let mut r = LineReader::new(512);
        let mut buf = Vec::with_capacity(512);
        let cap = buf.capacity();
        r.feed(b"NOOP\r\nNOOP\r\n");
        assert_eq!(r.take_line(&mut buf), Ok(true));
        assert_eq!(r.take_line(&mut buf), Ok(true));
        assert_eq!(
            buf.capacity(),
            cap,
            "buffer should be reused, not reallocated"
        );
    }

    // ---- DataReader ----

    fn read_all(chunks: &[&[u8]], max: usize) -> (String, DataStatus) {
        let mut d = DataReader::new(max);
        let mut status = DataStatus::NeedMore;
        for c in chunks {
            let (_, s) = d.feed(c);
            status = s;
            if d.is_complete() {
                break;
            }
        }
        (String::from_utf8_lossy(d.body()).into_owned(), status)
    }

    #[test]
    fn reads_a_simple_body() {
        let (body, status) = read_all(&[b"Subject: hi\r\n\r\nHello.\r\n.\r\n"], 1 << 20);
        assert_eq!(status, DataStatus::Complete);
        assert_eq!(body, "Subject: hi\r\n\r\nHello.\r\n");
    }

    #[test]
    fn empty_body_is_valid() {
        let (body, status) = read_all(&[b".\r\n"], 1 << 20);
        assert_eq!(status, DataStatus::Complete);
        assert_eq!(body, "");
    }

    #[test]
    fn removes_dot_stuffing() {
        // The sender doubled the dot; the receiver restores the original line.
        let (body, _) = read_all(&[b"..leading dot\r\n.\r\n"], 1 << 20);
        assert_eq!(body, ".leading dot\r\n");
    }

    #[test]
    fn a_dot_inside_a_line_is_untouched() {
        let (body, _) = read_all(&[b"version 1.0 here\r\n.\r\n"], 1 << 20);
        assert_eq!(body, "version 1.0 here\r\n");
    }

    #[test]
    fn a_line_of_dots_is_not_the_terminator() {
        let (body, status) = read_all(&[b"...\r\n.\r\n"], 1 << 20);
        assert_eq!(status, DataStatus::Complete);
        assert_eq!(body, "..\r\n");
    }

    #[test]
    fn terminator_split_across_every_boundary() {
        // The marker is five bytes, so try breaking it at each one.
        let full = b"Hi\r\n.\r\n";
        for split in 0..full.len() {
            let (a, b) = full.split_at(split);
            let (body, status) = read_all(&[a, b], 1 << 20);
            assert_eq!(status, DataStatus::Complete, "split at {split}");
            assert_eq!(body, "Hi\r\n", "split at {split}");
        }
    }

    #[test]
    fn terminator_split_one_byte_at_a_time() {
        let full: &[u8] = b"A\r\n..B\r\n.\r\n";
        let mut d = DataReader::new(1 << 20);
        for &b in full {
            d.feed(&[b]);
        }
        assert!(d.is_complete());
        assert_eq!(d.body(), b"A\r\n.B\r\n");
    }

    #[test]
    fn reports_bytes_consumed_so_pipelined_commands_survive() {
        let mut d = DataReader::new(1 << 20);
        let input = b"Hi\r\n.\r\nQUIT\r\n";
        let (used, status) = d.feed(input);
        assert_eq!(status, DataStatus::Complete);
        assert_eq!(used, 7, "should stop at the terminator");
        assert_eq!(&input[used..], b"QUIT\r\n");
    }

    #[test]
    fn oversized_body_keeps_scanning_to_the_terminator() {
        let mut d = DataReader::new(8);
        let (_, status) = d.feed(b"aaaaaaaaaaaaaaaaaaaaaaaa\r\n.\r\n");
        assert_eq!(status, DataStatus::TooLarge);
        // Terminator still found, so the connection stays usable and the
        // client can be told 552 instead of having the socket dropped.
        assert!(d.is_complete());
        assert_eq!(d.len(), 8);
    }

    #[test]
    fn feeding_after_completion_consumes_nothing() {
        let mut d = DataReader::new(1 << 20);
        d.feed(b"Hi\r\n.\r\n");
        assert_eq!(d.feed(b"more"), (0, DataStatus::Complete));
        assert_eq!(d.body(), b"Hi\r\n");
    }

    #[test]
    fn bare_cr_in_body_is_preserved() {
        let (body, _) = read_all(&[b"a\rb\r\n.\r\n"], 1 << 20);
        assert_eq!(body, "a\rb\r\n");
    }

    #[test]
    fn consecutive_crs_are_preserved() {
        let (body, _) = read_all(&[b"a\r\r\nb\r\n.\r\n"], 1 << 20);
        assert_eq!(body, "a\r\r\nb\r\n");
    }
}
