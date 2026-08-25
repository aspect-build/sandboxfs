// proto3 wire primitives: the reader/writer every codec in this crate is built from, plus the two
// leaf messages (`Digest`, map entries) that appear in all of them.

/// SHA-256 via the platform's CommonCrypto (native; no crate, no hand-rolled crypto).
mod cc {
    extern "C" {
        pub fn CC_SHA256(data: *const u8, len: u32, md: *mut u8) -> *mut u8;
    }
}

pub fn sha256_hex(b: &[u8]) -> String {
    let mut out = [0u8; 32];
    unsafe { cc::CC_SHA256(b.as_ptr(), b.len() as u32, out.as_mut_ptr()) };
    hex_of(&out)
}

pub(crate) fn hex_of(b: &[u8]) -> String {
    const D: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(b.len() * 2);
    for &x in b {
        s.push(D[(x >> 4) as usize] as char);
        s.push(D[(x & 0xf) as usize] as char);
    }
    s
}

pub struct Reader<'a> {
    pub(crate) b: &'a [u8],
    pub(crate) i: usize,
    /// False once a frame turned out to be truncated or malformed. A parser drives the loop with
    /// `next_key` and checks this once at the end.
    pub ok: bool,
}

impl<'a> Reader<'a> {
    pub fn new(b: &'a [u8]) -> Self {
        Reader { b, i: 0, ok: true }
    }

    pub fn varint(&mut self) -> u64 {
        let mut shift = 0u64;
        let mut v = 0u64;
        while self.i < self.b.len() {
            let byte = self.b[self.i];
            self.i += 1;
            v |= ((byte & 0x7f) as u64) << shift;
            if byte & 0x80 == 0 {
                return v;
            }
            shift += 7;
            if shift > 63 {
                break;
            }
        }
        self.ok = false;
        0
    }

    /// Length-delimited payload slice; None (and ok=false) on truncation.
    pub fn len_slice(&mut self) -> Option<&'a [u8]> {
        let n = self.varint() as usize;
        if !self.ok || self.b.len().checked_sub(self.i).map_or(true, |rem| rem < n) {
            self.ok = false;
            return None;
        }
        let s = &self.b[self.i..self.i + n];
        self.i += n;
        Some(s)
    }

    /// The next (field number, wire type), or None at the end of the frame -- and on a malformed
    /// one, which is why a parser checks `ok` once at the end instead of after every field.
    pub fn next_key(&mut self) -> Option<(u64, u64)> {
        if !self.ok || self.i >= self.b.len() {
            return None;
        }
        let key = self.varint();
        self.ok.then(|| (key >> 3, key & 7))
    }

    /// The next varint in a packed field, or None at the end / on a malformed one.
    pub fn next_varint(&mut self) -> Option<u64> {
        if !self.ok || self.i >= self.b.len() {
            return None;
        }
        let v = self.varint();
        self.ok.then_some(v)
    }

    pub fn skip(&mut self, wire: u64) {
        match wire {
            0 => {
                self.varint();
            }
            1 => {
                self.i += 8;
                if self.i > self.b.len() {
                    self.ok = false;
                }
            }
            2 => {
                self.len_slice();
            }
            5 => {
                self.i += 4;
                if self.i > self.b.len() {
                    self.ok = false;
                }
            }
            _ => self.ok = false,
        }
    }
}

pub(crate) fn string(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

/// `Digest{ string hash = 1; int64 size_bytes = 2; }`.
pub(crate) fn parse_digest(b: &[u8]) -> Option<(String, u64)> {
    let (mut hash, mut size) = (String::new(), 0u64);
    let mut r = Reader::new(b);
    while let Some((field, wire)) = r.next_key() {
        match (field, wire) {
            (1, 2) => hash = string(r.len_slice()?),
            (2, 0) => size = r.varint(),
            (_, w) => r.skip(w),
        }
    }
    r.ok.then_some((hash, size))
}

/// Just the hash half, for the many callers that ignore size.
pub(crate) fn digest_hash(b: &[u8]) -> Option<String> {
    parse_digest(b).map(|(h, _)| h)
}

/// `map<string, string>` entry: {1: key, 2: value}. Also the shape of any two-string message.
pub(crate) fn parse_map_entry(b: &[u8]) -> Option<(String, String)> {
    let (mut k, mut v) = (String::new(), String::new());
    let mut r = Reader::new(b);
    while let Some((field, wire)) = r.next_key() {
        match (field, wire) {
            (1, 2) => k = string(r.len_slice()?),
            (2, 2) => v = string(r.len_slice()?),
            (_, w) => r.skip(w),
        }
    }
    r.ok.then_some((k, v))
}

#[derive(Default)]
pub struct Writer {
    pub out: Vec<u8>,
}

impl Writer {
    pub(crate) fn varint(&mut self, mut v: u64) {
        while v >= 0x80 {
            self.out.push((v as u8 & 0x7f) | 0x80);
            v >>= 7;
        }
        self.out.push(v as u8);
    }
    pub(crate) fn key(&mut self, field: u32, wire: u32) {
        self.varint(((field << 3) | wire) as u64);
    }
    pub(crate) fn bytes(&mut self, field: u32, b: &[u8]) {
        self.key(field, 2);
        self.varint(b.len() as u64);
        self.out.extend_from_slice(b);
    }
    pub fn str(&mut self, field: u32, s: &str) {
        self.bytes(field, s.as_bytes());
    }
    pub fn msg(&mut self, field: u32, b: &[u8]) {
        self.bytes(field, b);
    }
    pub(crate) fn uint(&mut self, field: u32, v: u64) {
        self.key(field, 0);
        self.varint(v);
    }
    pub(crate) fn bool(&mut self, field: u32, v: bool) {
        self.uint(field, if v { 1 } else { 0 });
    }
}

pub(crate) fn encode_digest(hash: &str, size: u64) -> Vec<u8> {
    let mut w = Writer::default();
    if !hash.is_empty() {
        w.str(1, hash);
    }
    if size != 0 {
        w.uint(2, size);
    }
    w.out
}

