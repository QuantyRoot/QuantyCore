//! A streaming tar reader: POSIX ustar, GNU (long names and links,
//! base-256 numbers) and PAX extended headers.
//!
//! Entries are read in order from any `Read`, so a gzip compressed layer
//! is unpacked with `Archive::new(GzipReader::new(file))` without being
//! held in memory. Data a caller does not read is skipped when it asks for
//! the next entry.
//!
//! Nothing here touches the file system, and paths are returned exactly
//! as stored. Making them safe to create is the caller's job;
//! [`safe_relative`] is the check it needs first.

use std::io::{self, Read};

const BLOCK: usize = 512;

/// Long names, long links and PAX headers are held in memory while the
/// entry they describe is read; this bounds what one costs.
pub const MAX_METADATA: u64 = 1 << 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Truncated,
    BadChecksum,
    BadNumber,
    /// One zero block followed by something other than a second one.
    LoneZeroBlock,
    MetadataTooLarge(u64),
    BadPax,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Truncated => f.write_str("tar archive truncated"),
            Error::BadChecksum => f.write_str("tar header checksum mismatch"),
            Error::BadNumber => f.write_str("invalid numeric field in tar header"),
            Error::LoneZeroBlock => f.write_str("a zero block not followed by another"),
            Error::MetadataTooLarge(n) => write!(f, "tar metadata entry of {n} bytes"),
            Error::BadPax => f.write_str("malformed PAX extended header"),
        }
    }
}

impl std::error::Error for Error {}

impl From<Error> for io::Error {
    fn from(e: Error) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidData, e)
    }
}

/// OCI whiteouts (`.wh.<name>` and `.wh..wh..opq`) are ordinary regular
/// files here; the caller handles them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Regular,
    HardLink,
    Symlink,
    Char,
    Block,
    Directory,
    Fifo,
    Other(u8),
}

impl Kind {
    fn from_byte(b: u8) -> Kind {
        match b {
            b'0' | 0 => Kind::Regular,
            b'1' => Kind::HardLink,
            b'2' => Kind::Symlink,
            b'3' => Kind::Char,
            b'4' => Kind::Block,
            b'5' => Kind::Directory,
            b'6' => Kind::Fifo,
            other => Kind::Other(other),
        }
    }

    /// These carry no data whatever their size field says, as GNU tar
    /// and Go's archive/tar read them.
    fn header_only(self) -> bool {
        matches!(
            self,
            Kind::HardLink
                | Kind::Symlink
                | Kind::Char
                | Kind::Block
                | Kind::Directory
                | Kind::Fifo
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    pub path: Vec<u8>,
    /// Target of a symlink, or the earlier entry a hard link refers to.
    pub link: Vec<u8>,
    pub kind: Kind,
    pub mode: u32,
    pub uid: u64,
    pub gid: u64,
    pub mtime: i64,
    /// As recorded. Kinds that carry no data read as empty even when this
    /// is not zero.
    pub size: u64,
    pub dev_major: u32,
    pub dev_minor: u32,
}

/// Values from PAX records. An empty value in a per-entry record cancels
/// a global one and lets the header field through (POSIX pax, "keyword=").
#[derive(Default)]
struct Pax {
    path: Option<Vec<u8>>,
    linkpath: Option<Vec<u8>>,
    size: Option<Vec<u8>>,
    uid: Option<Vec<u8>>,
    gid: Option<Vec<u8>>,
    mtime: Option<Vec<u8>>,
}

impl Pax {
    fn parse(&mut self, data: &[u8]) -> Result<(), Error> {
        let mut rest = data;
        while !rest.is_empty() {
            // "%d %s=%s\n", where the length counts the whole record.
            let space = rest.iter().position(|&b| b == b' ').ok_or(Error::BadPax)?;
            let len: usize = std::str::from_utf8(&rest[..space])
                .ok()
                .and_then(|s| s.parse().ok())
                .ok_or(Error::BadPax)?;
            if len <= space + 1 || len > rest.len() || rest[len - 1] != b'\n' {
                return Err(Error::BadPax);
            }
            let record = &rest[space + 1..len - 1];
            let eq = record
                .iter()
                .position(|&b| b == b'=')
                .ok_or(Error::BadPax)?;
            let value = record[eq + 1..].to_vec();
            match &record[..eq] {
                b"path" => self.path = Some(value),
                b"linkpath" => self.linkpath = Some(value),
                b"size" => self.size = Some(value),
                b"uid" => self.uid = Some(value),
                b"gid" => self.gid = Some(value),
                b"mtime" => self.mtime = Some(value),
                _ => {}
            }
            rest = &rest[len..];
        }
        Ok(())
    }

    /// Folds a global header in: there an empty value removes the key.
    fn merge_global(&mut self, g: Pax) {
        let set = |slot: &mut Option<Vec<u8>>, v: Option<Vec<u8>>| {
            if let Some(v) = v {
                *slot = if v.is_empty() { None } else { Some(v) };
            }
        };
        set(&mut self.path, g.path);
        set(&mut self.linkpath, g.linkpath);
        set(&mut self.size, g.size);
        set(&mut self.uid, g.uid);
        set(&mut self.gid, g.gid);
        set(&mut self.mtime, g.mtime);
    }
}

/// The per-entry value if present, else the global one; `None` when
/// neither applies or the per-entry record is empty.
fn pick<'a>(local: &'a Option<Vec<u8>>, global: &'a Option<Vec<u8>>) -> Option<&'a [u8]> {
    match local {
        Some(v) if v.is_empty() => None,
        Some(v) => Some(v),
        None => global.as_deref(),
    }
}

fn pax_u64(v: &[u8]) -> Result<u64, Error> {
    std::str::from_utf8(v)
        .ok()
        .filter(|s| s.bytes().all(|b| b.is_ascii_digit()))
        .and_then(|s| s.parse().ok())
        .ok_or(Error::BadPax)
}

/// Seconds, with an optional fraction that is dropped.
fn pax_time(v: &[u8]) -> Result<i64, Error> {
    let whole = v.split(|&b| b == b'.').next().unwrap_or(v);
    let (neg, digits) = match whole.split_first() {
        Some((b'-', d)) => (true, d),
        _ => (false, whole),
    };
    let n = pax_u64(digits)?;
    let n = i64::try_from(n).map_err(|_| Error::BadPax)?;
    Ok(if neg { -n } else { n })
}

pub struct Archive<R> {
    inner: R,
    remaining: u64,
    padding: u64,
    global: Pax,
    done: bool,
}

impl<R: Read> Archive<R> {
    pub fn new(inner: R) -> Self {
        Archive {
            inner,
            remaining: 0,
            padding: 0,
            global: Pax::default(),
            done: false,
        }
    }

    /// The reader, positioned after the two zero blocks once
    /// `next_entry` has returned `None`. Reading it to the end checks a
    /// gzip trailer that the tar data alone never reaches.
    pub fn into_inner(self) -> R {
        self.inner
    }

    /// Errors carry an [`Error`] as `InvalidData`, or come from the
    /// inner reader unchanged.
    pub fn next_entry(&mut self) -> io::Result<Option<Entry<'_, R>>> {
        if self.done {
            return Ok(None);
        }
        self.skip(self.remaining + self.padding)?;
        self.remaining = 0;
        self.padding = 0;
        let mut long_name: Option<Vec<u8>> = None;
        let mut long_link: Option<Vec<u8>> = None;
        let mut local = Pax::default();
        loop {
            let mut block = [0u8; BLOCK];
            self.read_exact(&mut block)?;
            if block.iter().all(|&b| b == 0) {
                self.read_exact(&mut block)?;
                if block.iter().any(|&b| b != 0) {
                    return Err(Error::LoneZeroBlock.into());
                }
                self.done = true;
                return Ok(None);
            }
            check_sum(&block)?;
            let size = unsigned(&block[124..136])?;
            let typeflag = block[156];
            if matches!(typeflag, b'L' | b'K' | b'x' | b'g') {
                if size > MAX_METADATA {
                    return Err(Error::MetadataTooLarge(size).into());
                }
                let mut data = vec![0; size as usize];
                self.read_exact(&mut data)?;
                self.skip(pad(size))?;
                match typeflag {
                    b'L' => long_name = Some(until_nul(&data).to_vec()),
                    b'K' => long_link = Some(until_nul(&data).to_vec()),
                    b'x' => local.parse(&data)?,
                    _ => {
                        let mut g = Pax::default();
                        g.parse(&data)?;
                        self.global.merge_global(g);
                    }
                }
                continue;
            }
            let header = self.header(&block, size, long_name, long_link, &local)?;
            self.remaining = if header.kind.header_only() {
                0
            } else {
                header.size
            };
            self.padding = pad(self.remaining);
            return Ok(Some(Entry {
                header,
                archive: self,
            }));
        }
    }

    fn header(
        &self,
        block: &[u8; BLOCK],
        size: u64,
        long_name: Option<Vec<u8>>,
        long_link: Option<Vec<u8>>,
        local: &Pax,
    ) -> Result<Header, Error> {
        let g = &self.global;
        let kind = Kind::from_byte(block[156]);
        // Only POSIX ustar has the prefix field; GNU keeps other fields
        // in those bytes and marks itself with "ustar  ".
        let ustar = &block[257..263] == b"ustar\0";
        let path = match pick(&local.path, &g.path) {
            Some(p) => p.to_vec(),
            None => long_name.unwrap_or_else(|| {
                let name = until_nul(&block[0..100]);
                let prefix = until_nul(&block[345..500]);
                if ustar && !prefix.is_empty() {
                    [prefix, b"/", name].concat()
                } else {
                    name.to_vec()
                }
            }),
        };
        let link = match pick(&local.linkpath, &g.linkpath) {
            Some(p) => p.to_vec(),
            None => long_link.unwrap_or_else(|| until_nul(&block[157..257]).to_vec()),
        };
        let field = |pax: Option<&[u8]>, raw: &[u8]| match pax {
            Some(v) => pax_u64(v),
            None => unsigned(raw),
        };
        let (dev_major, dev_minor) = if matches!(kind, Kind::Char | Kind::Block) {
            let major = u32::try_from(unsigned(&block[329..337])?);
            let minor = u32::try_from(unsigned(&block[337..345])?);
            (
                major.map_err(|_| Error::BadNumber)?,
                minor.map_err(|_| Error::BadNumber)?,
            )
        } else {
            (0, 0)
        };
        Ok(Header {
            path,
            link,
            kind,
            mode: u32::try_from(unsigned(&block[100..108])?).map_err(|_| Error::BadNumber)?,
            uid: field(pick(&local.uid, &g.uid), &block[108..116])?,
            gid: field(pick(&local.gid, &g.gid), &block[116..124])?,
            mtime: match pick(&local.mtime, &g.mtime) {
                Some(v) => pax_time(v)?,
                None => numeric(&block[136..148])?,
            },
            size: match pick(&local.size, &g.size) {
                Some(v) => pax_u64(v)?,
                None => size,
            },
            dev_major,
            dev_minor,
        })
    }

    fn read_exact(&mut self, buf: &mut [u8]) -> io::Result<()> {
        self.inner.read_exact(buf).map_err(|e| {
            if e.kind() == io::ErrorKind::UnexpectedEof {
                Error::Truncated.into()
            } else {
                e
            }
        })
    }

    fn skip(&mut self, n: u64) -> io::Result<()> {
        let copied = io::copy(&mut (&mut self.inner).take(n), &mut io::sink())?;
        if copied < n {
            return Err(Error::Truncated.into());
        }
        Ok(())
    }
}

/// One entry; reading it yields the entry's data and then end of file.
pub struct Entry<'a, R> {
    header: Header,
    archive: &'a mut Archive<R>,
}

impl<R> Entry<'_, R> {
    pub fn header(&self) -> &Header {
        &self.header
    }
}

impl<R: Read> Read for Entry<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let a = &mut *self.archive;
        let n = buf
            .len()
            .min(usize::try_from(a.remaining).unwrap_or(usize::MAX));
        if n == 0 {
            return Ok(0);
        }
        let got = a.inner.read(&mut buf[..n])?;
        if got == 0 {
            return Err(Error::Truncated.into());
        }
        a.remaining -= got as u64;
        Ok(got)
    }
}

/// Returns `path` relative to the root it is unpacked into, with leading
/// "./" removed, or `None` if it is absolute or has a ".." component
/// anywhere. A layer that writes through "../" escapes the directory it
/// is unpacked into. An empty result names the root itself.
pub fn safe_relative(path: &[u8]) -> Option<&[u8]> {
    if path.is_empty() {
        return None;
    }
    let mut p = path;
    while let Some(rest) = p.strip_prefix(b"./") {
        p = rest;
        while let Some(rest) = p.strip_prefix(b"/") {
            p = rest;
        }
    }
    if p == b"." {
        p = b"";
    }
    if p.first() == Some(&b'/') || p.split(|&b| b == b'/').any(|c| c == b"..") {
        return None;
    }
    Some(p)
}

fn pad(size: u64) -> u64 {
    (BLOCK as u64 - size % BLOCK as u64) % BLOCK as u64
}

fn until_nul(field: &[u8]) -> &[u8] {
    match field.iter().position(|&b| b == 0) {
        Some(i) => &field[..i],
        None => field,
    }
}

/// The checksum is the sum of the header bytes with the checksum field
/// read as eight spaces. Some old writers summed signed bytes, so both
/// sums are accepted, as GNU tar accepts them.
fn check_sum(block: &[u8; BLOCK]) -> Result<(), Error> {
    let want = unsigned(&block[148..156]).map_err(|_| Error::BadChecksum)?;
    let mut sum_u: u64 = 0;
    let mut sum_s: i64 = 0;
    for (i, &b) in block.iter().enumerate() {
        let b = if (148..156).contains(&i) { b' ' } else { b };
        sum_u += u64::from(b);
        sum_s += i64::from(b as i8);
    }
    if want == sum_u || i64::try_from(want) == Ok(sum_s) {
        Ok(())
    } else {
        Err(Error::BadChecksum)
    }
}

fn unsigned(field: &[u8]) -> Result<u64, Error> {
    u64::try_from(numeric(field)?).map_err(|_| Error::BadNumber)
}

/// Octal, padded with spaces or NULs; or, when the first byte has its
/// high bit set, GNU base-256: big-endian two's complement in the rest of
/// the field, with 0x80 marking a positive and 0xff a negative number.
fn numeric(field: &[u8]) -> Result<i64, Error> {
    if field.first().is_some_and(|&b| b & 0x80 != 0) {
        let inv = if field[0] & 0x40 != 0 { 0xff } else { 0 };
        let mut x: u64 = 0;
        for (i, &c) in field.iter().enumerate() {
            let mut c = c ^ inv;
            if i == 0 {
                c &= 0x7f;
            }
            if x >> 56 != 0 {
                return Err(Error::BadNumber);
            }
            x = (x << 8) | u64::from(c);
        }
        if x >> 63 != 0 {
            return Err(Error::BadNumber);
        }
        let x = x as i64;
        return Ok(if inv == 0xff { !x } else { x });
    }
    let trimmed: &[u8] = {
        let start = field.iter().position(|&b| b != b' ' && b != 0);
        let end = field.iter().rposition(|&b| b != b' ' && b != 0);
        match (start, end) {
            (Some(s), Some(e)) => &field[s..=e],
            _ => b"",
        }
    };
    let mut x: i64 = 0;
    for &c in trimmed {
        if !(b'0'..=b'7').contains(&c) {
            return Err(Error::BadNumber);
        }
        x = x
            .checked_mul(8)
            .and_then(|x| x.checked_add(i64::from(c - b'0')))
            .ok_or(Error::BadNumber)?;
    }
    Ok(x)
}

// The tests compare with the system's tar and make symlinks.
#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::inflate::GzipReader;
    use std::os::unix::ffi::OsStrExt;
    use std::path::{Path, PathBuf};
    use std::process::Command;

    const LONG_DIR: &str = "d/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/";
    const LONG_FILE: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.txt";

    struct Expected {
        path: Vec<u8>,
        kind: Kind,
        link: &'static [u8],
        content: Vec<u8>,
    }

    /// A directory with every case the layer reader must get right, and
    /// what an archive of it has to contain.
    fn fixture(root: &Path) -> Vec<Expected> {
        let d = root.join("d");
        std::fs::create_dir_all(root.join(LONG_DIR)).unwrap();
        let mut big = Vec::with_capacity(1_600_000);
        let mut x: u64 = 0x2545_f491_4f6c_dd1d;
        while big.len() < 1_600_000 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            big.extend_from_slice(&x.to_le_bytes());
        }
        let latin1 = std::ffi::OsStr::from_bytes(b"caf\xe9");
        let files: [(PathBuf, &[u8]); 5] = [
            (root.join(LONG_DIR).join(LONG_FILE), b"deep"),
            (d.join("big"), &big),
            (d.join(latin1), b"not utf-8"),
            (d.join("empty"), b""),
            (d.join("file"), b"linked twice\n"),
        ];
        for (p, c) in &files {
            std::fs::write(p, c).unwrap();
        }
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(d.join("file"), std::fs::Permissions::from_mode(0o640)).unwrap();
        std::fs::hard_link(d.join("file"), d.join("hard")).unwrap();
        std::os::unix::fs::symlink("../x", d.join("link")).unwrap();
        let ok = Command::new("mkfifo").arg(d.join("pipe")).status().unwrap();
        assert!(ok.success());

        let e = |path: &[u8], kind, link, content: &[u8]| Expected {
            path: path.to_vec(),
            kind,
            link,
            content: content.to_vec(),
        };
        let long = format!("{LONG_DIR}{LONG_FILE}");
        assert!(long.len() > 100);
        let mut want = vec![
            e(b"d/", Kind::Directory, b"", b""),
            e(LONG_DIR.as_bytes(), Kind::Directory, b"", b""),
            e(long.as_bytes(), Kind::Regular, b"", b"deep"),
            e(b"d/big", Kind::Regular, b"", &big),
            e(b"d/caf\xe9", Kind::Regular, b"", b"not utf-8"),
            e(b"d/empty", Kind::Regular, b"", b""),
            e(b"d/file", Kind::Regular, b"", b"linked twice\n"),
            e(b"d/hard", Kind::HardLink, b"d/file", b""),
            e(b"d/link", Kind::Symlink, b"../x", b""),
            e(b"d/pipe", Kind::Fifo, b"", b""),
        ];
        want.sort_by(|a, b| a.path.cmp(&b.path));
        want
    }

    fn read_all<R: Read>(archive: &mut Archive<R>) -> io::Result<Vec<(Header, Vec<u8>)>> {
        let mut out = Vec::new();
        while let Some(mut entry) = archive.next_entry()? {
            let mut data = Vec::new();
            entry.read_to_end(&mut data)?;
            out.push((entry.header().clone(), data));
        }
        Ok(out)
    }

    fn check(got: Vec<(Header, Vec<u8>)>, want: &[Expected], uid: u64, what: &str) {
        let mut got = got;
        got.sort_by(|a, b| a.0.path.cmp(&b.0.path));
        let paths: Vec<_> = got.iter().map(|(h, _)| h.path.clone()).collect();
        let want_paths: Vec<_> = want.iter().map(|w| w.path.clone()).collect();
        assert_eq!(paths, want_paths, "{what}");
        for ((h, data), w) in got.iter().zip(want) {
            let at = format!("{what}: {}", String::from_utf8_lossy(&h.path));
            assert_eq!(h.kind, w.kind, "{at}");
            assert_eq!(h.link, w.link, "{at}");
            assert_eq!(h.size, w.content.len() as u64, "{at}");
            assert!(*data == w.content, "{at}: content differs");
            assert_eq!(
                (h.uid, h.gid, h.mtime),
                (uid, uid + 1, 1_700_000_000),
                "{at}"
            );
            if h.path == b"d/file" {
                assert_eq!(h.mode & 0o7777, 0o640, "{at}");
            }
        }
    }

    fn gnu_tar(root: &Path, format: &str, uid: u64, extra: &[&str]) -> Vec<u8> {
        let out = Command::new("tar")
            .args([
                "--sort=name",
                "--mtime=@1700000000",
                "-b",
                "1",
                "-c",
                "-f",
                "-",
            ])
            .arg(format!("--format={format}"))
            .arg(format!("--owner=o:{uid}"))
            .arg(format!("--group=g:{}", uid + 1))
            .args(extra)
            .arg("-C")
            .arg(root)
            .arg("d")
            .output()
            .expect("GNU tar must be installed");
        assert!(
            out.status.success(),
            "tar: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        out.stdout
    }

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(name: &str) -> Self {
            let p = std::env::temp_dir().join(format!("quanty-{name}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&p);
            std::fs::create_dir_all(&p).unwrap();
            TempDir(p)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn gnu_tar_archives_read_back_in_every_format() {
        let dir = TempDir::new("tar-formats");
        let want = fixture(&dir.0);
        // Above 07777777, so GNU format has to write uid and gid in
        // base-256 and PAX in extended records; ustar cannot hold it.
        let big_uid = 3_000_000;
        for (format, uid) in [("gnu", big_uid), ("pax", big_uid), ("ustar", 1000)] {
            let bytes = gnu_tar(&dir.0, format, uid, &[]);
            let got = read_all(&mut Archive::new(&bytes[..])).unwrap();
            check(got, &want, uid, format);
        }

        let gz = gnu_tar(&dir.0, "pax", 1000, &["-z"]);
        let mut archive = Archive::new(GzipReader::new(&gz[..]));
        check(read_all(&mut archive).unwrap(), &want, 1000, "pax.gz");
        let mut rest = archive.into_inner();
        io::copy(&mut rest, &mut io::sink()).expect("gzip trailer");
    }

    #[test]
    fn damaged_archives_are_errors() {
        let dir = TempDir::new("tar-damage");
        fixture(&dir.0);
        let bytes = gnu_tar(&dir.0, "gnu", 1000, &[]);
        assert!(read_all(&mut Archive::new(&bytes[..])).is_ok());

        let mut bad = bytes.clone();
        bad[3] ^= 0x20;
        let e = read_all(&mut Archive::new(&bad[..])).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::InvalidData);
        assert_eq!(
            e.into_inner().unwrap().to_string(),
            "tar header checksum mismatch"
        );

        // With a blocking factor of 1 the archive ends at the second zero
        // block, so every shorter prefix lacks something.
        let n = bytes.len();
        let mut cuts: Vec<usize> = (0..64).map(|i| n * i / 64 + i % 7).collect();
        cuts.extend([n - 1024, n - 512, n - 1]);
        for cut in cuts {
            let r = read_all(&mut Archive::new(&bytes[..cut]));
            assert!(r.is_err(), "prefix of {cut} of {n} bytes was accepted");
        }
    }

    fn block(name: &[u8], typeflag: u8, size: u64, uid: u64, dev: (u32, u32)) -> [u8; BLOCK] {
        let mut b = [0u8; BLOCK];
        b[..name.len()].copy_from_slice(name);
        let mut put = |at: usize, width: usize, v: u64| {
            let s = format!("{v:0w$o}\0", w = width - 1);
            b[at..at + width].copy_from_slice(s.as_bytes());
        };
        put(100, 8, 0o644);
        put(108, 8, uid);
        put(116, 8, 0);
        put(124, 12, size);
        put(136, 12, 0);
        put(329, 8, u64::from(dev.0));
        put(337, 8, u64::from(dev.1));
        b[156] = typeflag;
        b[257..265].copy_from_slice(b"ustar\x0000");
        b[148..156].fill(b' ');
        let sum: u32 = b.iter().map(|&x| u32::from(x)).sum();
        b[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
        b
    }

    fn with_data(out: &mut Vec<u8>, header: [u8; BLOCK], data: &[u8]) {
        out.extend_from_slice(&header);
        out.extend_from_slice(data);
        out.resize(out.len() + pad(data.len() as u64) as usize, 0);
    }

    fn pax_records(kind: u8, records: &[(&str, &str)]) -> Vec<u8> {
        let mut data = Vec::new();
        for (k, v) in records {
            // The length counts its own digits.
            let body = k.len() + v.len() + 3;
            let mut len = body + 1;
            while len != body + len.to_string().len() {
                len = body + len.to_string().len();
            }
            data.extend_from_slice(format!("{len} {k}={v}\n").as_bytes());
        }
        let mut out = Vec::new();
        with_data(
            &mut out,
            block(b"pax", kind, data.len() as u64, 0, (0, 0)),
            &data,
        );
        out
    }

    #[test]
    fn pax_records_override_header_fields() {
        let mut ar = pax_records(b'g', &[("uid", "7"), ("mtime", "5.25")]);
        ar.extend(pax_records(
            b'x',
            &[
                ("size", "5"),
                ("path", "long/renamed"),
                ("comment", "ignored"),
            ],
        ));
        // The size field says 0; only the PAX size finds the data.
        with_data(&mut ar, block(b"one", b'0', 0, 0, (0, 0)), b"hello");
        ar.extend(pax_records(b'x', &[("uid", "")]));
        with_data(&mut ar, block(b"two", b'0', 3, 9, (0, 0)), b"abc");
        with_data(&mut ar, block(b"tty", b'3', 0, 0, (4, 64)), b"");
        ar.extend_from_slice(&[0; 2 * BLOCK]);

        let got = read_all(&mut Archive::new(&ar[..])).unwrap();
        let summary: Vec<_> = got
            .iter()
            .map(|(h, d)| (h.path.as_slice(), h.uid, h.mtime, d.as_slice()))
            .collect();
        assert_eq!(
            summary,
            [
                (&b"long/renamed"[..], 7, 5, &b"hello"[..]),
                (b"two", 9, 5, b"abc"),
                (b"tty", 7, 5, b""),
            ]
        );
        assert_eq!(got[2].0.kind, Kind::Char);
        assert_eq!((got[2].0.dev_major, got[2].0.dev_minor), (4, 64));
    }

    #[test]
    fn numbers_in_octal_and_base_256() {
        assert_eq!(numeric(b"0000644\0"), Ok(0o644));
        assert_eq!(numeric(b"  17 \0\0\0"), Ok(0o17));
        assert_eq!(numeric(b"\0\0\0\0\0\0\0\0"), Ok(0));
        assert_eq!(numeric(b"0009\0"), Err(Error::BadNumber));
        let mut size = [0u8; 12];
        size[0] = 0x80;
        size[7] = 2;
        assert_eq!(numeric(&size), Ok(2 << 32));
        assert_eq!(numeric(&[0xff; 8]), Ok(-1));
        assert_eq!(
            numeric(&[0x80, 0x80, 0, 0, 0, 0, 0, 0, 0]),
            Err(Error::BadNumber)
        );
    }

    #[test]
    fn safe_relative_rejects_escapes() {
        let ok: [(&[u8], &[u8]); 6] = [
            (b"a/b", b"a/b"),
            (b"./a/b/", b"a/b/"),
            (b"././a", b"a"),
            (b"./", b""),
            (b"a/./b..c/..d", b"a/./b..c/..d"),
            (b".wh..wh..opq", b".wh..wh..opq"),
        ];
        for (input, want) in ok {
            assert_eq!(safe_relative(input), Some(want), "{input:?}");
        }
        let bad: [&[u8]; 7] = [
            b"",
            b"/etc/passwd",
            b"..",
            b"../x",
            b"./../x",
            b"a/../../x",
            b".//a/..",
        ];
        for input in bad {
            assert_eq!(safe_relative(input), None, "{input:?}");
        }
    }
}
