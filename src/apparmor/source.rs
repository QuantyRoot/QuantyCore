//! Profile text, where it came from, and how includes find more of it.
//!
//! Nothing below the loader reads files. Includes go through a
//! [`Resolver`] the caller provides; [`FsResolver`] is the one that reads
//! the file system the way `apparmor_parser` does.

use std::fmt;
use std::path::{Path, PathBuf};

/// Where a piece of text is: the file, and a byte offset in it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct Span {
    pub file: u32,
    pub offset: u32,
}

/// A position a person can find: file name, line and column, both
/// counted from one, the column in bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Location {
    pub file: String,
    pub line: u32,
    pub column: u32,
}

impl fmt::Display for Location {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}:{}", self.file, self.line, self.column)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Error {
    pub location: Option<Location>,
    pub message: String,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.location {
            Some(l) => write!(f, "{l}: {}", self.message),
            None => f.write_str(&self.message),
        }
    }
}

impl std::error::Error for Error {}

/// What a name given to `include` turned out to be.
pub enum Opened {
    NotFound,
    File(Vec<u8>),
    /// Names of the entries that are regular files, or symbolic links to
    /// them. Other entries are left out, as upstream skips them.
    Dir(Vec<Vec<u8>>),
}

/// Supplies the text of included files.
///
/// `include <name>` tries `dir/name` for each directory of the search
/// path in order; `include "name"` and `include name` open the name as
/// given, which upstream resolves against its working directory.
pub trait Resolver {
    fn search_path(&self) -> &[Vec<u8>];
    fn open(&mut self, path: &[u8]) -> Opened;
}

/// Resolves includes from the file system: the search path as
/// `apparmor_parser -I` would build it, relative names against `base`.
pub struct FsResolver {
    search: Vec<Vec<u8>>,
    base: PathBuf,
}

impl FsResolver {
    /// `/etc/apparmor.d` as the only search directory and relative names
    /// against `/`, which is how the boot service runs the parser.
    pub fn system() -> FsResolver {
        FsResolver::new(vec![PathBuf::from("/etc/apparmor.d")], "/")
    }

    pub fn new(search: Vec<PathBuf>, base: impl Into<PathBuf>) -> FsResolver {
        use std::os::unix::ffi::OsStrExt;
        let search = search
            .into_iter()
            .map(|p| {
                let mut b = p.as_os_str().as_bytes().to_vec();
                while b.len() > 1 && b.last() == Some(&b'/') {
                    b.pop();
                }
                b
            })
            .filter(|b| !b.is_empty())
            .collect();
        FsResolver {
            search,
            base: base.into(),
        }
    }
}

/// Larger files than this are refused: nothing in a profile tree comes
/// close, and an include of a device or a huge file must not exhaust
/// memory.
pub const MAX_FILE: u64 = 16 << 20;

impl Resolver for FsResolver {
    fn search_path(&self) -> &[Vec<u8>] {
        &self.search
    }

    fn open(&mut self, path: &[u8]) -> Opened {
        use std::io::Read;
        use std::os::unix::ffi::OsStrExt;
        let p = Path::new(std::ffi::OsStr::from_bytes(path));
        let full = self.base.join(p);
        let meta = match std::fs::metadata(&full) {
            Ok(m) => m,
            Err(_) => return Opened::NotFound,
        };
        if meta.is_dir() {
            let mut names = Vec::new();
            let Ok(rd) = std::fs::read_dir(&full) else {
                return Opened::NotFound;
            };
            for e in rd.flatten() {
                if std::fs::metadata(e.path()).is_ok_and(|m| m.is_file()) {
                    names.push(e.file_name().as_bytes().to_vec());
                }
            }
            names.sort();
            return Opened::Dir(names);
        }
        if !meta.is_file() || meta.len() > MAX_FILE {
            return Opened::NotFound;
        }
        let mut text = Vec::new();
        match std::fs::File::open(&full) {
            Ok(f) => match f.take(MAX_FILE + 1).read_to_end(&mut text) {
                Ok(_) if text.len() as u64 <= MAX_FILE => Opened::File(text),
                _ => Opened::NotFound,
            },
            Err(_) => Opened::NotFound,
        }
    }
}

/// A resolver over files held in memory, for tests and for callers that
/// build profiles without a file system.
#[derive(Default)]
pub struct MemResolver {
    pub search: Vec<Vec<u8>>,
    pub files: Vec<(Vec<u8>, Vec<u8>)>,
}

impl Resolver for MemResolver {
    fn search_path(&self) -> &[Vec<u8>] {
        &self.search
    }

    fn open(&mut self, path: &[u8]) -> Opened {
        if let Some((_, t)) = self.files.iter().find(|(p, _)| p == path) {
            return Opened::File(t.clone());
        }
        let mut prefix = path.to_vec();
        prefix.push(b'/');
        let mut names: Vec<Vec<u8>> = self
            .files
            .iter()
            .filter_map(|(p, _)| p.strip_prefix(prefix.as_slice()))
            .filter(|rest| !rest.contains(&b'/'))
            .map(|rest| rest.to_vec())
            .collect();
        if names.is_empty() {
            return Opened::NotFound;
        }
        names.sort();
        Opened::Dir(names)
    }
}

/// Every file read while parsing, so that positions can be shown.
#[derive(Default)]
pub struct Sources {
    files: Vec<(String, Vec<u8>)>,
}

impl Sources {
    pub(crate) fn add(&mut self, name: String, text: Vec<u8>) -> u32 {
        self.files.push((name, text));
        (self.files.len() - 1) as u32
    }

    pub(crate) fn text(&self, file: u32) -> &[u8] {
        &self.files[file as usize].1
    }

    pub fn len(&self) -> usize {
        self.files.len()
    }

    pub fn is_empty(&self) -> bool {
        self.files.is_empty()
    }

    pub fn total_bytes(&self) -> usize {
        self.files.iter().map(|(_, t)| t.len()).sum()
    }

    pub fn locate(&self, span: Span) -> Location {
        let (name, text) = &self.files[span.file as usize];
        let off = (span.offset as usize).min(text.len());
        let before = &text[..off];
        let line = before.iter().filter(|&&b| b == b'\n').count() as u32 + 1;
        let start = before
            .iter()
            .rposition(|&b| b == b'\n')
            .map_or(0, |i| i + 1);
        Location {
            file: name.clone(),
            line,
            column: (off - start) as u32 + 1,
        }
    }

    pub(crate) fn error_at(&self, span: Span, message: impl Into<String>) -> Error {
        Error {
            location: Some(self.locate(span)),
            message: message.into(),
        }
    }
}
