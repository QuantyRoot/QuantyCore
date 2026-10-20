//! DEFLATE (RFC 1951) and the gzip container around it (RFC 1952), as a
//! streaming reader.
//!
//! Memory per reader is fixed: a 64 KiB ring that holds the 32 KiB window
//! plus output not yet handed to the caller, a 32 KiB input buffer, and
//! the Huffman tables. Nothing grows with the input, so a hostile stream
//! can cost time proportional to its length and nothing more.
//!
//! Concatenated gzip members, which `cat a.gz b.gz` produces, decode back
//! to back as one stream. Bytes after the last member that are not another
//! member are an error, as they are for `gzip -t`.

use std::io::{self, Read};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Truncated,
    BadMagic,
    BadMethod(u8),
    /// Flag bits 5 to 7 are reserved and must be zero.
    ReservedFlags(u8),
    HeaderCrc,
    BadBlockType,
    /// LEN of a stored block is not the complement of NLEN.
    StoredLength,
    /// More than 286 literal/length or 30 distance codes, or a code
    /// length repeat that has nothing to repeat or runs past the end.
    BadCodeLengths,
    OverSubscribed,
    Incomplete,
    MissingEndOfBlock,
    /// A bit pattern no code was assigned to, or one of the symbols the
    /// fixed tables reserve (286, 287, distances 30, 31).
    BadCode,
    DistanceTooFar,
    Crc {
        expected: u32,
        actual: u32,
    },
    Size {
        expected: u32,
        actual: u32,
    },
    /// The reader returned an error before and its state is not trusted.
    EarlierFailure,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Truncated => f.write_str("gzip stream truncated"),
            Error::BadMagic => f.write_str("not a gzip member"),
            Error::BadMethod(m) => write!(f, "compression method {m}, only 8 exists"),
            Error::ReservedFlags(b) => write!(f, "reserved gzip flags set: {b:#04x}"),
            Error::HeaderCrc => f.write_str("gzip header CRC mismatch"),
            Error::BadBlockType => f.write_str("deflate block type 3"),
            Error::StoredLength => f.write_str("stored block LEN does not match NLEN"),
            Error::BadCodeLengths => f.write_str("invalid code length sequence"),
            Error::OverSubscribed => f.write_str("over-subscribed Huffman code"),
            Error::Incomplete => f.write_str("incomplete Huffman code"),
            Error::MissingEndOfBlock => f.write_str("no code for end of block"),
            Error::BadCode => f.write_str("invalid Huffman code"),
            Error::DistanceTooFar => f.write_str("distance reaches before the output"),
            Error::Crc { expected, actual } => {
                write!(f, "CRC-32 {actual:08x}, trailer says {expected:08x}")
            }
            Error::Size { expected, actual } => {
                write!(f, "size {actual} mod 2^32, trailer says {expected}")
            }
            Error::EarlierFailure => f.write_str("gzip reader failed earlier"),
        }
    }
}

impl std::error::Error for Error {}

impl From<Error> for io::Error {
    fn from(e: Error) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidData, e)
    }
}

/// Decompresses a whole gzip file held in memory.
pub fn gunzip(data: &[u8]) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    match GzipReader::new(data).read_to_end(&mut out) {
        Ok(_) => Ok(out),
        Err(e) => Err(e
            .get_ref()
            .and_then(|e| e.downcast_ref::<Error>())
            .copied()
            .unwrap_or(Error::EarlierFailure)),
    }
}

const WINDOW: usize = 32 * 1024;
const RING: usize = 2 * WINDOW;
const MASK: usize = RING - 1;
const MAX_MATCH: usize = 258;
const INPUT_BUF: usize = 32 * 1024;

const LEN_BASE: [u16; 29] = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131,
    163, 195, 227, 258,
];
const LEN_EXTRA: [u8; 29] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
];
const DIST_BASE: [u16; 30] = [
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537,
    2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577,
];
const DIST_EXTRA: [u8; 30] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13,
    13,
];
const CLEN_ORDER: [usize; 19] = [
    16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
];

/// Streams the decompressed content of a gzip file. The trailer of each
/// member is checked when the reader reaches it, so corruption at the end
/// of a member surfaces only to a caller that reads to the end.
///
/// The inner reader is expected to block: `WouldBlock` is passed up like
/// any other error and leaves this reader failed.
pub struct GzipReader<R> {
    bits: Bits<R>,
    inflate: Box<Inflate>,
    state: State,
    members: u64,
    crc: u32,
    size: u32,
    failed: Option<Error>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum State {
    Header,
    Body,
    Trailer,
    Done,
}

impl<R: Read> GzipReader<R> {
    pub fn new(inner: R) -> Self {
        GzipReader {
            bits: Bits {
                inner,
                buf: vec![0; INPUT_BUF].into_boxed_slice(),
                pos: 0,
                len: 0,
                bitbuf: 0,
                bitcnt: 0,
                eof: false,
            },
            inflate: Box::new(Inflate::new()),
            state: State::Header,
            members: 0,
            crc: 0,
            size: 0,
            failed: None,
        }
    }

    fn step(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            if self.inflate.unread() > 0 {
                let n = self.inflate.deliver(buf);
                self.crc = crc32_update(self.crc, &buf[..n]);
                self.size = self.size.wrapping_add(n as u32);
                return Ok(n);
            }
            match self.state {
                State::Header => {
                    if self.members > 0 && self.bits.at_end()? {
                        self.state = State::Done;
                        continue;
                    }
                    self.header()?;
                    self.inflate.reset();
                    self.crc = 0;
                    self.size = 0;
                    self.state = State::Body;
                }
                State::Body => {
                    if self.inflate.run(&mut self.bits)? {
                        self.state = State::Trailer;
                    }
                }
                State::Trailer => {
                    self.bits.align();
                    let expected = self.bits.take(16)? | (self.bits.take(16)? << 16);
                    let size = self.bits.take(16)? | (self.bits.take(16)? << 16);
                    if expected != self.crc {
                        return Err(Error::Crc {
                            expected,
                            actual: self.crc,
                        }
                        .into());
                    }
                    if size != self.size {
                        return Err(Error::Size {
                            expected: size,
                            actual: self.size,
                        }
                        .into());
                    }
                    self.members += 1;
                    self.state = State::Header;
                }
                State::Done => return Ok(0),
            }
        }
    }

    fn header(&mut self) -> io::Result<()> {
        let mut crc = 0;
        let mut fixed = [0u8; 10];
        for b in &mut fixed {
            *b = self.header_byte(&mut crc)?;
        }
        if fixed[0] != 0x1f || fixed[1] != 0x8b {
            return Err(Error::BadMagic.into());
        }
        if fixed[2] != 8 {
            return Err(Error::BadMethod(fixed[2]).into());
        }
        let flags = fixed[3];
        if flags & 0xe0 != 0 {
            return Err(Error::ReservedFlags(flags).into());
        }
        if flags & 0x04 != 0 {
            let xlen = u16::from(self.header_byte(&mut crc)?)
                | (u16::from(self.header_byte(&mut crc)?) << 8);
            for _ in 0..xlen {
                self.header_byte(&mut crc)?;
            }
        }
        // FNAME, then FCOMMENT: zero terminated, of any length, skipped
        // without being stored.
        for flag in [0x08, 0x10] {
            if flags & flag != 0 {
                while self.header_byte(&mut crc)? != 0 {}
            }
        }
        if flags & 0x02 != 0 {
            let want = self.bits.take(16)?;
            if want != crc & 0xffff {
                return Err(Error::HeaderCrc.into());
            }
        }
        Ok(())
    }

    fn header_byte(&mut self, crc: &mut u32) -> io::Result<u8> {
        let b = self.bits.take(8)? as u8;
        *crc = crc32_update(*crc, &[b]);
        Ok(b)
    }
}

impl<R: Read> Read for GzipReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if let Some(e) = self.failed {
            return Err(e.into());
        }
        if buf.is_empty() {
            return Ok(0);
        }
        let r = self.step(buf);
        if let Err(e) = &r {
            self.failed = Some(
                e.get_ref()
                    .and_then(|e| e.downcast_ref::<Error>())
                    .copied()
                    .unwrap_or(Error::EarlierFailure),
            );
        }
        r
    }
}

/// Bits are consumed least significant first, as RFC 1951 packs them.
/// Bits above `bitcnt` in `bitbuf` are always zero, which lets a lookup
/// near the end of the input read past the last real bit safely.
struct Bits<R> {
    inner: R,
    buf: Box<[u8]>,
    pos: usize,
    len: usize,
    bitbuf: u64,
    bitcnt: u32,
    eof: bool,
}

impl<R: Read> Bits<R> {
    /// Tops the bit buffer up to at least 56 bits unless the input ends.
    #[inline]
    fn fill(&mut self) -> io::Result<()> {
        if self.pos + 8 <= self.len {
            let word = u64::from_le_bytes(
                self.buf[self.pos..self.pos + 8]
                    .try_into()
                    .expect("eight bytes"),
            );
            let bytes = (63 - self.bitcnt) >> 3;
            let newcnt = self.bitcnt + 8 * bytes;
            self.bitbuf |= (word << self.bitcnt) & (u64::MAX >> (64 - newcnt));
            self.bitcnt = newcnt;
            self.pos += bytes as usize;
            return Ok(());
        }
        self.fill_slow()
    }

    #[cold]
    fn fill_slow(&mut self) -> io::Result<()> {
        loop {
            // Stops at 56 to 63 bits, never 64: a full 64 would make the
            // shifts in `fill` and `take` overflow.
            while self.bitcnt < 56 && self.pos < self.len {
                self.bitbuf |= u64::from(self.buf[self.pos]) << self.bitcnt;
                self.bitcnt += 8;
                self.pos += 1;
            }
            if self.bitcnt >= 56 || self.eof {
                return Ok(());
            }
            self.refill_buf()?;
        }
    }

    fn refill_buf(&mut self) -> io::Result<()> {
        debug_assert_eq!(self.pos, self.len);
        loop {
            match self.inner.read(&mut self.buf) {
                Ok(n) => {
                    self.pos = 0;
                    self.len = n;
                    self.eof = n == 0;
                    return Ok(());
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
    }

    #[inline]
    fn take(&mut self, n: u32) -> io::Result<u32> {
        if self.bitcnt < n {
            self.fill()?;
            if self.bitcnt < n {
                return Err(Error::Truncated.into());
            }
        }
        let v = (self.bitbuf & ((1u64 << n) - 1)) as u32;
        self.bitbuf >>= n;
        self.bitcnt -= n;
        Ok(v)
    }

    fn align(&mut self) {
        let drop = self.bitcnt % 8;
        self.bitbuf >>= drop;
        self.bitcnt -= drop;
    }

    fn at_end(&mut self) -> io::Result<bool> {
        self.fill()?;
        Ok(self.bitcnt == 0)
    }
}

const FAST_BITS: u32 = 9;

/// A canonical Huffman code. Codes up to FAST_BITS long are found with
/// one lookup of the next FAST_BITS input bits; longer ones, rare in
/// practice, by walking the code lengths in canonical order.
struct Huffman {
    /// Symbol << 4 | length, or 0 where the code is longer or unassigned.
    fast: [u16; 1 << FAST_BITS],
    counts: [u16; 16],
    symbols: [u16; 288],
}

impl Huffman {
    fn new() -> Self {
        Huffman {
            fast: [0; 1 << FAST_BITS],
            counts: [0; 16],
            symbols: [0; 288],
        }
    }

    /// A single code of one bit, the other pattern unused, is accepted for
    /// both alphabets, as zlib and Go accept it: rejecting what they
    /// accept would only refuse layers every other runtime unpacks.
    /// `degenerate` also allows no codes at all, which RFC 1951 allows for
    /// distances.
    fn build(&mut self, lengths: &[u8], degenerate: bool) -> Result<(), Error> {
        self.counts = [0; 16];
        for &l in lengths {
            self.counts[usize::from(l)] += 1;
        }
        self.counts[0] = 0;
        let mut left: i32 = 1;
        for len in 1..16 {
            left <<= 1;
            left -= i32::from(self.counts[len]);
            if left < 0 {
                return Err(Error::OverSubscribed);
            }
        }
        if left > 0 {
            let used: u16 = self.counts.iter().sum();
            if !((used == 1 && self.counts[1] == 1) || (degenerate && used == 0)) {
                return Err(Error::Incomplete);
            }
        }
        let mut offsets = [0u16; 16];
        for len in 1..15 {
            offsets[len + 1] = offsets[len] + self.counts[len];
        }
        for (sym, &l) in lengths.iter().enumerate() {
            if l != 0 {
                let o = &mut offsets[usize::from(l)];
                self.symbols[usize::from(*o)] = sym as u16;
                *o += 1;
            }
        }
        self.fast = [0; 1 << FAST_BITS];
        let mut code: u32 = 0;
        let mut index = 0;
        for len in 1..=FAST_BITS {
            for _ in 0..self.counts[len as usize] {
                let sym = self.symbols[index];
                let mut i = (code.reverse_bits() >> (32 - len)) as usize;
                while i < self.fast.len() {
                    self.fast[i] = (sym << 4) | len as u16;
                    i += 1 << len;
                }
                code += 1;
                index += 1;
            }
            code <<= 1;
        }
        Ok(())
    }

    #[inline]
    fn decode<R: Read>(&self, bits: &mut Bits<R>) -> io::Result<u16> {
        let e = self.fast[(bits.bitbuf & ((1 << FAST_BITS) - 1)) as usize];
        let len = u32::from(e & 15);
        if len != 0 && len <= bits.bitcnt {
            bits.bitbuf >>= len;
            bits.bitcnt -= len;
            return Ok(e >> 4);
        }
        self.decode_slow(bits)
    }

    #[cold]
    fn decode_slow<R: Read>(&self, bits: &mut Bits<R>) -> io::Result<u16> {
        let mut code: i32 = 0;
        let mut first: i32 = 0;
        let mut index: i32 = 0;
        for len in 1..16u32 {
            if len > bits.bitcnt {
                return Err(Error::Truncated.into());
            }
            code |= ((bits.bitbuf >> (len - 1)) & 1) as i32;
            let count = i32::from(self.counts[len as usize]);
            if code - first < count {
                bits.bitbuf >>= len;
                bits.bitcnt -= len;
                return Ok(self.symbols[(index + code - first) as usize]);
            }
            index += count;
            first = (first + count) << 1;
            code <<= 1;
        }
        Err(Error::BadCode.into())
    }
}

#[derive(Clone, Copy)]
enum Block {
    Header,
    Stored(usize),
    Codes,
    Done,
}

/// The DEFLATE decoder proper. Output goes into a ring of twice the
/// window: everything between `read` and `write` is waiting for the
/// caller, and the 32 KiB before `write` is the history matches copy from.
/// Decoding pauses while fewer than MAX_MATCH bytes of the ring are free,
/// so one symbol never has to be suspended halfway.
struct Inflate {
    ring: [u8; RING],
    write: usize,
    read: usize,
    /// Bytes of history available, capped at the window.
    have: usize,
    block: Block,
    last: bool,
    lit: Huffman,
    dist: Huffman,
}

impl Inflate {
    fn new() -> Self {
        Inflate {
            ring: [0; RING],
            write: 0,
            read: 0,
            have: 0,
            block: Block::Header,
            last: false,
            lit: Huffman::new(),
            dist: Huffman::new(),
        }
    }

    fn reset(&mut self) {
        self.have = 0;
        self.block = Block::Header;
        self.last = false;
    }

    fn unread(&self) -> usize {
        self.write.wrapping_sub(self.read)
    }

    fn deliver(&mut self, buf: &mut [u8]) -> usize {
        let n = buf.len().min(self.unread());
        let r = self.read & MASK;
        let first = n.min(RING - r);
        buf[..first].copy_from_slice(&self.ring[r..r + first]);
        buf[first..n].copy_from_slice(&self.ring[..n - first]);
        self.read = self.read.wrapping_add(n);
        n
    }

    /// Decodes until the ring is nearly full or the stream ends; returns
    /// whether it ended.
    fn run<R: Read>(&mut self, bits: &mut Bits<R>) -> io::Result<bool> {
        loop {
            match self.block {
                Block::Header => {
                    if self.last {
                        self.block = Block::Done;
                        continue;
                    }
                    self.last = bits.take(1)? == 1;
                    match bits.take(2)? {
                        0 => {
                            bits.align();
                            let len = bits.take(16)?;
                            let nlen = bits.take(16)?;
                            if len != !nlen & 0xffff {
                                return Err(Error::StoredLength.into());
                            }
                            self.block = Block::Stored(len as usize);
                        }
                        1 => {
                            self.fixed_tables()?;
                            self.block = Block::Codes;
                        }
                        2 => {
                            self.dynamic_tables(bits)?;
                            self.block = Block::Codes;
                        }
                        _ => return Err(Error::BadBlockType.into()),
                    }
                }
                Block::Stored(left) => {
                    let left = self.stored(bits, left)?;
                    if left > 0 {
                        self.block = Block::Stored(left);
                        return Ok(false);
                    }
                    self.block = Block::Header;
                }
                Block::Codes => {
                    if !self.codes(bits)? {
                        return Ok(false);
                    }
                    self.block = Block::Header;
                }
                Block::Done => return Ok(true),
            }
        }
    }

    fn stored<R: Read>(&mut self, bits: &mut Bits<R>, mut left: usize) -> io::Result<usize> {
        while left > 0 {
            let room = RING - self.unread();
            if room == 0 {
                break;
            }
            // Whole bytes already pulled into the bit buffer come first.
            if bits.bitcnt >= 8 {
                let b = bits.take(8)? as u8;
                self.push(b);
                left -= 1;
                continue;
            }
            if bits.pos == bits.len {
                bits.refill_buf()?;
                if bits.eof {
                    return Err(Error::Truncated.into());
                }
            }
            let w = self.write & MASK;
            let n = left.min(room).min(bits.len - bits.pos).min(RING - w);
            self.ring[w..w + n].copy_from_slice(&bits.buf[bits.pos..bits.pos + n]);
            bits.pos += n;
            self.write = self.write.wrapping_add(n);
            self.have = (self.have + n).min(WINDOW);
            left -= n;
        }
        Ok(left)
    }

    fn codes<R: Read>(&mut self, bits: &mut Bits<R>) -> io::Result<bool> {
        while self.unread() <= RING - MAX_MATCH {
            if bits.bitcnt < 48 {
                bits.fill()?;
            }
            let sym = self.lit.decode(bits)?;
            if sym < 256 {
                self.push(sym as u8);
                continue;
            }
            if sym == 256 {
                return Ok(true);
            }
            let i = usize::from(sym - 257);
            if i >= LEN_BASE.len() {
                return Err(Error::BadCode.into());
            }
            let len = usize::from(LEN_BASE[i]) + bits.take(u32::from(LEN_EXTRA[i]))? as usize;
            let d = usize::from(self.dist.decode(bits)?);
            if d >= DIST_BASE.len() {
                return Err(Error::BadCode.into());
            }
            let dist = usize::from(DIST_BASE[d]) + bits.take(u32::from(DIST_EXTRA[d]))? as usize;
            if dist > self.have {
                return Err(Error::DistanceTooFar.into());
            }
            self.copy_match(dist, len);
        }
        Ok(false)
    }

    #[inline]
    fn push(&mut self, b: u8) {
        self.ring[self.write & MASK] = b;
        self.write = self.write.wrapping_add(1);
        if self.have < WINDOW {
            self.have += 1;
        }
    }

    #[inline]
    fn copy_match(&mut self, dist: usize, len: usize) {
        let d = self.write & MASK;
        if d >= dist && d + len <= RING {
            let s = d - dist;
            // An overlapping copy repeats the last `dist` bytes; each pass
            // can copy everything written so far, doubling the run.
            let mut done = 0;
            while done < len {
                let n = (len - done).min(dist + done);
                self.ring.copy_within(s..s + n, d + done);
                done += n;
            }
        } else {
            let s = d.wrapping_sub(dist);
            for i in 0..len {
                self.ring[(d + i) & MASK] = self.ring[s.wrapping_add(i) & MASK];
            }
        }
        self.write = self.write.wrapping_add(len);
        self.have = (self.have + len).min(WINDOW);
    }

    fn fixed_tables(&mut self) -> Result<(), Error> {
        let mut l = [0u8; 288];
        l[..144].fill(8);
        l[144..256].fill(9);
        l[256..280].fill(7);
        l[280..].fill(8);
        self.lit.build(&l, false)?;
        // 30 distance codes in a 5 bit space; 30 and 31 complete the code
        // and are invalid if they appear.
        self.dist.build(&[5; 32], false)
    }

    fn dynamic_tables<R: Read>(&mut self, bits: &mut Bits<R>) -> io::Result<()> {
        let nlit = bits.take(5)? as usize + 257;
        let ndist = bits.take(5)? as usize + 1;
        let nclen = bits.take(4)? as usize + 4;
        if nlit > 286 || ndist > 30 {
            return Err(Error::BadCodeLengths.into());
        }
        let mut clen = [0u8; 19];
        for &i in &CLEN_ORDER[..nclen] {
            clen[i] = bits.take(3)? as u8;
        }
        let mut table = Huffman::new();
        table.build(&clen, false)?;
        let total = nlit + ndist;
        let mut lengths = [0u8; 286 + 30];
        let mut i = 0;
        while i < total {
            bits.fill()?;
            let sym = table.decode(bits)?;
            let (value, repeat) = match sym {
                0..=15 => (sym as u8, 1),
                16 => {
                    if i == 0 {
                        return Err(Error::BadCodeLengths.into());
                    }
                    (lengths[i - 1], 3 + bits.take(2)? as usize)
                }
                17 => (0, 3 + bits.take(3)? as usize),
                _ => (0, 11 + bits.take(7)? as usize),
            };
            if i + repeat > total {
                return Err(Error::BadCodeLengths.into());
            }
            lengths[i..i + repeat].fill(value);
            i += repeat;
        }
        if lengths[256] == 0 {
            return Err(Error::MissingEndOfBlock.into());
        }
        self.lit.build(&lengths[..nlit], false)?;
        self.dist.build(&lengths[nlit..total], true)?;
        Ok(())
    }
}

/// The IEEE CRC-32 gzip uses, eight bytes per step.
fn crc32_update(crc: u32, data: &[u8]) -> u32 {
    let t = &CRC_TABLES;
    let mut c = !crc;
    let (chunks, rest) = data.as_chunks::<8>();
    for ch in chunks {
        let lo = u32::from_le_bytes([ch[0], ch[1], ch[2], ch[3]]) ^ c;
        let hi = u32::from_le_bytes([ch[4], ch[5], ch[6], ch[7]]);
        c = t[7][(lo & 0xff) as usize]
            ^ t[6][((lo >> 8) & 0xff) as usize]
            ^ t[5][((lo >> 16) & 0xff) as usize]
            ^ t[4][(lo >> 24) as usize]
            ^ t[3][(hi & 0xff) as usize]
            ^ t[2][((hi >> 8) & 0xff) as usize]
            ^ t[1][((hi >> 16) & 0xff) as usize]
            ^ t[0][(hi >> 24) as usize];
    }
    for &b in rest {
        c = t[0][((c ^ u32::from(b)) & 0xff) as usize] ^ (c >> 8);
    }
    !c
}

static CRC_TABLES: [[u32; 256]; 8] = crc_tables();

const fn crc_tables() -> [[u32; 256]; 8] {
    let mut t = [[0u32; 256]; 8];
    let mut i = 0;
    while i < 256 {
        let mut c = i as u32;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 != 0 {
                0xedb8_8320 ^ (c >> 1)
            } else {
                c >> 1
            };
            k += 1;
        }
        t[0][i] = c;
        i += 1;
    }
    let mut i = 0;
    while i < 256 {
        let mut s = 1;
        while s < 8 {
            let prev = t[s - 1][i];
            t[s][i] = (prev >> 8) ^ t[0][(prev & 0xff) as usize];
            s += 1;
        }
        i += 1;
    }
    t
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::{Command, Stdio};

    /// Runs `python3 -I -c script` with `input` on stdin; the reference
    /// encoders are zlib's, reached through Python.
    fn python(script: &str, input: &[u8]) -> Vec<u8> {
        let mut child = Command::new("python3")
            .args(["-I", "-c", script])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .expect("python3 must be installed");
        let mut stdin = child.stdin.take().unwrap();
        let input = input.to_vec();
        let writer = std::thread::spawn(move || {
            use std::io::Write;
            stdin.write_all(&input).unwrap();
        });
        let out = child.wait_with_output().unwrap();
        writer.join().unwrap();
        assert!(out.status.success(), "python3 failed");
        out.stdout
    }

    fn gzip_level(data: &[u8], level: u32) -> Vec<u8> {
        let script = format!(
            "import sys,gzip;sys.stdout.buffer.write(gzip.compress(sys.stdin.buffer.read(),{level}))"
        );
        python(&script, data)
    }

    struct Rng(u64);

    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }

        fn below(&mut self, n: usize) -> usize {
            (self.next() % n as u64) as usize
        }
    }

    /// Text from a small vocabulary interleaved with runs of random bytes,
    /// so the encoder uses literals, short and long matches together.
    fn mixed(n: usize, seed: u64) -> Vec<u8> {
        let words: [&[u8]; 8] = [
            b"layer ",
            b"image ",
            b"digest ",
            b"sha256:",
            b"\n",
            b"manifest ",
            b"{\"a\":1} ",
            b"tar ",
        ];
        let mut rng = Rng(seed);
        let mut out = Vec::with_capacity(n);
        while out.len() < n {
            if rng.below(4) == 0 {
                for _ in 0..rng.below(64) {
                    out.push(rng.next() as u8);
                }
            } else {
                out.extend_from_slice(words[rng.below(words.len())]);
            }
        }
        out.truncate(n);
        out
    }

    fn btype(gz: &[u8]) -> u8 {
        assert_eq!(gz[3], 0, "the deflate data must start at byte 10");
        (gz[10] >> 1) & 3
    }

    #[test]
    fn the_three_block_types_and_an_empty_member() {
        let empty = gzip_level(b"", 6);
        assert_eq!(gunzip(&empty), Ok(Vec::new()));
        assert_eq!(gunzip(&[]), Err(Error::Truncated));

        let long = mixed(200_000, 1);
        let cases: [(&[u8], u32, u8); 3] = [
            (&long, 0, 0),
            (b"a short line, short enough for fixed codes", 1, 1),
            (&long, 6, 2),
        ];
        for (data, level, want) in cases {
            let gz = gzip_level(data, level);
            assert_eq!(btype(&gz), want, "level {level}");
            assert_eq!(gunzip(&gz).as_deref(), Ok(data), "level {level}");
        }
    }

    #[test]
    fn matches_across_the_window_survive_any_read_size() {
        // A 30000 byte block repeated: every match reaches about 30000
        // back, so copies keep crossing the end of the ring.
        let block = mixed(30_000, 2);
        let data: Vec<u8> = block.iter().copied().cycle().take(100 * 1024).collect();
        let gz = gzip_level(&data, 9);
        for chunk in [1, 7, 4096, 1 << 20] {
            let mut r = GzipReader::new(&gz[..]);
            let mut out = Vec::new();
            let mut buf = vec![0; chunk];
            loop {
                let n = r.read(&mut buf).unwrap();
                if n == 0 {
                    break;
                }
                out.extend_from_slice(&buf[..n]);
            }
            assert!(out == data, "read size {chunk}");
        }
    }

    #[test]
    fn header_fields_and_concatenated_members() {
        let dir = std::env::temp_dir().join(format!("quanty-gz-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("named.txt");
        let first = mixed(5000, 3);
        std::fs::write(&file, &first).unwrap();
        let out = Command::new("gzip")
            .args(["-N", "-c"])
            .arg(&file)
            .output()
            .expect("gzip must be installed");
        std::fs::remove_dir_all(&dir).unwrap();
        let mut gz = out.stdout;
        assert_eq!(gz[3] & 0x08, 0x08, "gzip -N sets FNAME");

        // FEXTRA, FCOMMENT and FHCRC; gzip writes none of them.
        let crafted = python(
            "import sys,zlib,struct\n\
             d=sys.stdin.buffer.read()\n\
             c=zlib.compressobj(6,zlib.DEFLATED,-15)\n\
             body=c.compress(d)+c.flush()\n\
             extra=b'QK\\x03\\x00abc'\n\
             h=b'\\x1f\\x8b\\x08\\x16'+b'\\0'*4+b'\\x00\\xff'+struct.pack('<H',len(extra))+extra+b'a comment\\0'\n\
             h+=struct.pack('<H',zlib.crc32(h)&0xffff)\n\
             sys.stdout.buffer.write(h+body+struct.pack('<II',zlib.crc32(d),len(d)))",
            b"second member",
        );
        let crafted_at = gz.len();
        gz.extend_from_slice(&crafted);
        gz.extend_from_slice(&gzip_level(b"", 6));
        let mut want = first.clone();
        want.extend_from_slice(b"second member");
        assert_eq!(gunzip(&gz), Ok(want));

        // 10 fixed bytes, XLEN, 7 bytes of extra, the comment, then the CRC.
        let mut bad = gz.clone();
        bad[crafted_at + 10 + 2 + 7 + 10] ^= 1;
        assert_eq!(gunzip(&bad), Err(Error::HeaderCrc));
    }

    #[test]
    fn corruption_and_truncation_are_errors() {
        let data = mixed(3000, 4);
        let gz = gzip_level(&data, 6);
        let n = gz.len();

        let mut bad = gz.clone();
        bad[n - 8] ^= 0x01;
        assert!(matches!(gunzip(&bad), Err(Error::Crc { .. })));
        let mut bad = gz.clone();
        bad[n - 4] ^= 0x01;
        assert!(matches!(gunzip(&bad), Err(Error::Size { .. })));
        let mut bad = gz.clone();
        bad.push(0);
        assert_eq!(gunzip(&bad), Err(Error::Truncated));
        bad.extend_from_slice(&[0; 9]);
        assert_eq!(gunzip(&bad), Err(Error::BadMagic));

        for cut in 0..n {
            assert!(gunzip(&gz[..cut]).is_err(), "prefix of {cut} bytes");
        }

        let mut r = GzipReader::new(&gz[..n - 1]);
        let e = io::copy(&mut r, &mut io::sink()).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::InvalidData);
        assert_eq!(r.read(&mut [0; 8]).unwrap_err().kind(), e.kind());
    }

    struct BitWriter {
        out: Vec<u8>,
        acc: u64,
        n: u32,
    }

    impl BitWriter {
        fn new() -> Self {
            BitWriter {
                out: Vec::new(),
                acc: 0,
                n: 0,
            }
        }

        fn bits(&mut self, v: u32, n: u32) -> &mut Self {
            self.acc |= u64::from(v) << self.n;
            self.n += n;
            while self.n >= 8 {
                self.out.push(self.acc as u8);
                self.acc >>= 8;
                self.n -= 8;
            }
            self
        }

        /// Huffman codes go most significant bit first (RFC 1951 3.1.1).
        fn code(&mut self, code: u32, len: u32) -> &mut Self {
            for i in (0..len).rev() {
                self.bits((code >> i) & 1, 1);
            }
            self
        }

        fn gzip(&mut self, content: &[u8]) -> Vec<u8> {
            let mut gz = vec![0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 255];
            if self.n > 0 {
                self.out.push(self.acc as u8);
            }
            gz.extend_from_slice(&self.out);
            gz.extend_from_slice(&crc32_update(0, content).to_le_bytes());
            gz.extend_from_slice(&(content.len() as u32).to_le_bytes());
            gz
        }
    }

    /// A dynamic block whose distance code has a single one bit code, the
    /// incomplete code RFC 1951 3.2.7 allows. Without `with_match` the
    /// literal/length code is incomplete too, which is not allowed.
    fn single_distance_code(with_match: bool) -> Vec<u8> {
        let mut w = BitWriter::new();
        w.bits(1, 1).bits(2, 2);
        w.bits(u32::from(with_match), 5).bits(0, 5).bits(14, 4);
        // Code length code lengths in CLEN_ORDER: 18 -> 1, 2 -> 2, 1 -> 2.
        for len in [0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 2] {
            w.bits(len, 3);
        }
        let (zeros, one, two) = ((0, 1), (0b10, 2), (0b11, 2));
        w.code(zeros.0, zeros.1).bits(97 - 11, 7);
        w.code(one.0, one.1);
        w.code(zeros.0, zeros.1).bits(138 - 11, 7);
        w.code(zeros.0, zeros.1).bits(20 - 11, 7);
        w.code(two.0, two.1);
        if with_match {
            w.code(two.0, two.1);
        }
        w.code(one.0, one.1);
        // 'a', length 3 at distance 1, end of block.
        w.code(0, 1).code(0b11, 2).code(0, 1).code(0b10, 2);
        w.gzip(b"aaaa")
    }

    #[test]
    fn hostile_blocks_are_rejected() {
        assert_eq!(gunzip(&single_distance_code(true)), Ok(b"aaaa".to_vec()));
        assert_eq!(gunzip(&single_distance_code(false)), Err(Error::Incomplete));

        // A literal/length code of end of block alone, one bit long: RFC
        // 1951 makes the exception for distances only, zlib and Go make it
        // for both, and so does this.
        let mut w = BitWriter::new();
        w.bits(1, 1).bits(2, 2).bits(0, 5).bits(0, 5).bits(14, 4);
        for len in [0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1] {
            w.bits(len, 3);
        }
        w.code(1, 1).bits(138 - 11, 7).code(1, 1).bits(118 - 11, 7);
        w.code(0, 1).code(0, 1).code(0, 1);
        assert_eq!(gunzip(&w.gzip(b"")), Ok(Vec::new()));

        let block_type_3 = BitWriter::new().bits(1, 1).bits(3, 2).gzip(b"");
        assert_eq!(gunzip(&block_type_3), Err(Error::BadBlockType));

        let stored = BitWriter::new()
            .bits(1, 1)
            .bits(0, 2)
            .bits(0, 5)
            .bits(5, 16)
            .bits(5, 16)
            .gzip(b"");
        assert_eq!(gunzip(&stored), Err(Error::StoredLength));

        // Fixed codes: 'a', then a match two bytes back after one byte.
        let far = BitWriter::new()
            .bits(1, 1)
            .bits(1, 2)
            .code(0x30 + 97, 8)
            .code(1, 7)
            .code(1, 5)
            .gzip(b"");
        assert_eq!(gunzip(&far), Err(Error::DistanceTooFar));

        let mut w = BitWriter::new();
        w.bits(1, 1).bits(2, 2).bits(0, 5).bits(0, 5).bits(0, 4);
        for _ in 0..4 {
            w.bits(1, 3);
        }
        assert_eq!(gunzip(&w.gzip(b"")), Err(Error::OverSubscribed));
    }

    #[test]
    fn mutated_streams_never_panic_and_stay_bounded() {
        let mut seeds = vec![
            gzip_level(&mixed(4000, 5), 0),
            gzip_level(b"fixed codes, fixed codes", 1),
            gzip_level(&mixed(6000, 6), 6),
            single_distance_code(true),
        ];
        let mut two = gzip_level(b"one", 9);
        two.extend_from_slice(&gzip_level(&mixed(2000, 7), 9));
        seeds.push(two);
        let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
        let mut rejected = 0;
        for _ in 0..4000 {
            let mut gz = seeds[rng.below(seeds.len())].clone();
            for _ in 0..1 + rng.below(4) {
                let i = rng.below(gz.len());
                match rng.below(3) {
                    0 => gz[i] ^= 1 << rng.below(8),
                    1 => gz[i] = rng.next() as u8,
                    _ => gz.truncate(i.max(1)),
                }
            }
            match gunzip(&gz) {
                // 258 bytes from two bits is the best DEFLATE can do.
                Ok(out) => assert!(out.len() <= gz.len() * 8 / 2 * 258),
                Err(_) => rejected += 1,
            }
        }
        assert!(rejected > 3000, "only {rejected} mutations rejected");
    }
}
