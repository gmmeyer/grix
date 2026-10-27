//! Minimal little-endian binary encoding used by the image and wire formats.

use alloc::vec::Vec;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DecodeError;

#[derive(Default)]
pub struct Writer {
    pub buf: Vec<u8>,
}

impl Writer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.buf.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    pub fn raw(&mut self, b: &[u8]) {
        self.buf.extend_from_slice(b);
    }

    pub fn u8(&mut self, v: u8) {
        self.buf.push(v);
    }

    pub fn u32(&mut self, v: u32) {
        self.raw(&v.to_le_bytes());
    }

    pub fn i32(&mut self, v: i32) {
        self.raw(&v.to_le_bytes());
    }

    pub fn u64(&mut self, v: u64) {
        self.raw(&v.to_le_bytes());
    }

    /// Length-prefixed byte string.
    pub fn bytes(&mut self, b: &[u8]) {
        self.u64(b.len() as u64);
        self.raw(b);
    }

    pub fn str(&mut self, s: &str) {
        self.bytes(s.as_bytes());
    }

    pub fn strs(&mut self, list: &[&str]) {
        self.u32(list.len() as u32);
        for s in list {
            self.str(s);
        }
    }
}

pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    pub fn take(&mut self, n: usize) -> Result<&'a [u8], DecodeError> {
        if self.remaining() < n {
            return Err(DecodeError);
        }
        let out = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(out)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], DecodeError> {
        let mut out = [0u8; N];
        out.copy_from_slice(self.take(N)?);
        Ok(out)
    }

    pub fn u8(&mut self) -> Result<u8, DecodeError> {
        Ok(self.take(1)?[0])
    }

    pub fn u32(&mut self) -> Result<u32, DecodeError> {
        Ok(u32::from_le_bytes(self.array()?))
    }

    pub fn i32(&mut self) -> Result<i32, DecodeError> {
        Ok(i32::from_le_bytes(self.array()?))
    }

    pub fn u64(&mut self) -> Result<u64, DecodeError> {
        Ok(u64::from_le_bytes(self.array()?))
    }

    pub fn bytes(&mut self) -> Result<&'a [u8], DecodeError> {
        let n = usize::try_from(self.u64()?).map_err(|_| DecodeError)?;
        self.take(n)
    }

    /// Everything left.
    pub fn rest(&mut self) -> &'a [u8] {
        let out = &self.buf[self.pos..];
        self.pos = self.buf.len();
        out
    }

    /// Fail unless everything was read.
    pub fn done(&self) -> Result<(), DecodeError> {
        if self.remaining() == 0 { Ok(()) } else { Err(DecodeError) }
    }

    pub fn str(&mut self) -> Result<&'a str, DecodeError> {
        core::str::from_utf8(self.bytes()?).map_err(|_| DecodeError)
    }

    pub fn strs(&mut self) -> Result<Vec<&'a str>, DecodeError> {
        let n = self.u32()? as usize;
        // Each string needs at least its 8-byte length prefix; reject absurd counts early.
        if n > self.remaining() / 8 {
            return Err(DecodeError);
        }
        (0..n).map(|_| self.str()).collect()
    }
}
