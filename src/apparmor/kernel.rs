//! The kernel's side: securityfs for loading, replacing, removing and
//! listing policy, and the procfs attribute that sets the profile for the
//! next exec.
//!
//! Both are plain files, so this module is `std::fs` and nothing else.
//! The exec transition is split into a decision the parent makes before
//! it clones and a write the child makes with its own syscalls, because a
//! runtime's child may not allocate between clone and exec.

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use super::binary::Unit;
use super::features::Features;

/// Where securityfs shows AppArmor on every distribution that mounts it.
pub const SECURITYFS: &str = "/sys/kernel/security/apparmor";

/// Where the module's parameters are, `enabled` and `available` among
/// them.
pub const PARAMETERS: &str = "/sys/module/apparmor/parameters";

/// AppArmor's directory in securityfs.
#[derive(Clone, Debug)]
pub struct Securityfs {
    dir: PathBuf,
}

/// A profile the kernel has loaded, as its `profiles` file lists it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Loaded {
    /// The name, with `:ns:` in front for a profile in another namespace.
    pub name: Vec<u8>,
    /// `enforce`, `complain`, `kill`, `unconfined`, `user` or `prompt`.
    pub mode: Vec<u8>,
}

impl Securityfs {
    pub fn system() -> Securityfs {
        Securityfs::at(SECURITYFS)
    }

    pub fn at(dir: impl Into<PathBuf>) -> Securityfs {
        Securityfs { dir: dir.into() }
    }

    /// The features the running kernel publishes, to compile against.
    pub fn features(&self) -> io::Result<Features> {
        Features::from_dir(&self.dir.join("features"))
    }

    /// Adds profiles; the kernel refuses one whose name is taken.
    pub fn load(&self, units: &[Unit]) -> io::Result<()> {
        self.write_units(".load", units)
    }

    /// Adds profiles or replaces the ones with the same name. Tasks
    /// confined by a replaced profile move to the new one.
    pub fn replace(&self, units: &[Unit]) -> io::Result<()> {
        self.write_units(".replace", units)
    }

    /// Removes a profile and its hats and children. `fqname` is
    /// [`fqname`] of the top unit.
    pub fn remove(&self, fqname: &[u8]) -> io::Result<()> {
        if fqname.is_empty() || fqname.contains(&0) {
            return Err(io::Error::from(io::ErrorKind::InvalidInput));
        }
        // libapparmor writes the terminating NUL along with the name.
        let mut b = Vec::with_capacity(fqname.len() + 1);
        b.extend_from_slice(fqname);
        b.push(0);
        write_once(&self.dir.join(".remove"), &b)
    }

    /// The profiles the kernel has loaded, in the order it lists them.
    pub fn profiles(&self) -> io::Result<Vec<Loaded>> {
        let mut text = Vec::new();
        File::open(self.dir.join("profiles"))?.read_to_end(&mut text)?;
        parse_profiles(&text)
    }

    // Each unit gets a write of its own, as apparmor_parser does: a
    // kernel without policy/set_load reads only the first profile of a
    // write, and hats must follow their parent.
    fn write_units(&self, file: &str, units: &[Unit]) -> io::Result<()> {
        let path = self.dir.join(file);
        for u in units {
            write_once(&path, &u.data)?;
        }
        Ok(())
    }
}

/// The name `.remove` takes for a unit: `:ns://name` in a namespace,
/// otherwise the name.
pub fn fqname(u: &Unit) -> Vec<u8> {
    match &u.namespace {
        None => u.name.clone(),
        Some(ns) => {
            let mut v = Vec::with_capacity(ns.len() + u.name.len() + 4);
            v.push(b':');
            v.extend_from_slice(ns);
            v.extend_from_slice(b"://");
            v.extend_from_slice(&u.name);
            v
        }
    }
}

// The kernel takes a policy in one write and reports the whole length or
// an error; a short write would leave a profile half read.
fn write_once(path: &Path, data: &[u8]) -> io::Result<()> {
    let mut f = OpenOptions::new().write(true).open(path)?;
    let n = f.write(data)?;
    if n != data.len() {
        return Err(io::Error::other("short write to securityfs"));
    }
    Ok(())
}

/// Reads the `profiles` file: one `name (mode)` per line.
pub fn parse_profiles(text: &[u8]) -> io::Result<Vec<Loaded>> {
    let mut out = Vec::new();
    for line in text.split(|&c| c == b'\n') {
        if line.is_empty() {
            continue;
        }
        let bad = || io::Error::new(io::ErrorKind::InvalidData, "bad profiles line");
        let body = line.strip_suffix(b")").ok_or_else(bad)?;
        let at = body.windows(2).rposition(|w| w == b" (").ok_or_else(bad)?;
        out.push(Loaded {
            name: body[..at].to_vec(),
            mode: body[at + 2..].to_vec(),
        });
    }
    Ok(out)
}

/// One of the two procfs files that set the profile for the next exec,
/// relative to `/proc`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AttrFile {
    /// `attr/apparmor/exec`, AppArmor's own, present since Linux 5.8.
    Stacking,
    /// `attr/exec`, shared by every security module that uses it.
    Legacy,
}

impl AttrFile {
    /// The path from the procfs root for the calling thread. A task may
    /// write only its own attribute, so a multi threaded caller must use
    /// `thread-self`; `self` is the thread group leader.
    pub fn path(self) -> &'static str {
        match self {
            AttrFile::Stacking => "thread-self/attr/apparmor/exec",
            AttrFile::Legacy => "thread-self/attr/exec",
        }
    }
}

/// What a probe of a file found, as far as the choice of attribute file
/// cares.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Probe {
    Present,
    Missing,
    Denied,
    Failed,
}

/// The value of a module parameter: `Y`, anything else, or no answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Param {
    Yes,
    No,
    Unread(Probe),
}

/// The files to try in order: the first, and the one to try when opening
/// the first fails.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Attempts {
    /// None when libapparmor would open a path that cannot exist.
    pub first: Option<AttrFile>,
    pub fallback: Option<AttrFile>,
}

/// libapparmor's choice of attribute file (proc_attr_base_init_once and
/// procattr_open), from the probe of `attr/apparmor/` and the module's
/// `enabled` and `available` parameters. The old shared file is used only
/// when the module says it is enabled or cannot be asked, never when it
/// says no: then the file belongs to another security module.
pub fn choose(stacking_dir: Probe, enabled: Param, available: Param) -> Attempts {
    #[derive(Clone, Copy, PartialEq)]
    enum Base {
        Stacking,
        Old,
        Unavailable,
    }
    let mut base = None;
    // proc_stacking_present: -1 unknown, which counts as true below.
    let mut present = -1;
    match stacking_dir {
        Probe::Present => {
            base = Some(Base::Stacking);
            present = 1;
        }
        Probe::Missing => present = 0,
        Probe::Denied => {
            present = 1;
            base = Some(Base::Stacking);
        }
        Probe::Failed => {}
    }
    if stacking_dir != Probe::Present {
        match enabled {
            Param::No => match available {
                Param::Yes => base = Some(Base::Stacking),
                Param::No => base = Some(Base::Unavailable),
                Param::Unread(_) => {}
            },
            Param::Yes => base = Some(Base::Old),
            Param::Unread(Probe::Denied) => {}
            Param::Unread(_) => base = Some(Base::Unavailable),
        }
    }
    let base = base.unwrap_or(if present != 0 {
        Base::Stacking
    } else {
        Base::Old
    });
    let first = match base {
        Base::Stacking => Some(AttrFile::Stacking),
        Base::Old => Some(AttrFile::Legacy),
        Base::Unavailable => None,
    };
    let fallback = if base != Base::Old && enabled != Param::No {
        Some(AttrFile::Legacy)
    } else {
        None
    };
    Attempts { first, fallback }
}

/// The parent's half of an exec transition: what to write, and where.
/// Prepared before the clone; the child only opens and writes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecTransition {
    /// `exec <profile>`, as libapparmor's aa_change_onexec writes it.
    pub command: Vec<u8>,
    pub attempts: Attempts,
}

impl ExecTransition {
    /// Prepares the transition to `profile` for this host, probing
    /// `/proc/thread-self/attr/apparmor/` and the module parameters.
    ///
    /// The child must open the attribute file on the host's procfs, and
    /// before it pivots into the container's root: a `/proc` the image
    /// controls can point the write elsewhere (CVE-2019-16884).
    pub fn prepare(profile: &[u8]) -> io::Result<ExecTransition> {
        let attempts = probe_host(Path::new("/proc"), Path::new(PARAMETERS));
        ExecTransition::with(profile, attempts)
    }

    /// The same, with the choice of files made by the caller.
    pub fn with(profile: &[u8], attempts: Attempts) -> io::Result<ExecTransition> {
        if profile.is_empty() || profile.contains(&0) {
            return Err(io::Error::from(io::ErrorKind::InvalidInput));
        }
        let mut command = Vec::with_capacity(profile.len() + 5);
        command.extend_from_slice(b"exec ");
        command.extend_from_slice(profile);
        Ok(ExecTransition { command, attempts })
    }

    /// Writes the command for the calling thread, for callers that may
    /// allocate. `proc` is the host's procfs root, normally `/proc`.
    pub fn apply(&self, proc: &Path) -> io::Result<()> {
        let open = |f: AttrFile| OpenOptions::new().write(true).open(proc.join(f.path()));
        // libapparmor falls back only when opening fails; a write the
        // kernel refuses is the answer.
        let mut file = match self.attempts.first.map(open) {
            Some(Ok(f)) => f,
            first => match (self.attempts.fallback, first) {
                (Some(fb), _) => open(fb)?,
                (None, Some(Err(e))) => return Err(e),
                (None, _) => return Err(io::Error::from(io::ErrorKind::NotFound)),
            },
        };
        let n = file.write(&self.command)?;
        if n != self.command.len() {
            return Err(io::Error::other("short write to the exec attribute"));
        }
        Ok(())
    }
}

/// Probes the files libapparmor probes, on this host.
pub fn probe_host(proc: &Path, params: &Path) -> Attempts {
    let dir = match std::fs::metadata(proc.join("thread-self/attr/apparmor/")) {
        Ok(_) => Probe::Present,
        Err(e) => probe_of(&e),
    };
    choose(
        dir,
        read_param(&params.join("enabled")),
        read_param(&params.join("available")),
    )
}

fn probe_of(e: &io::Error) -> Probe {
    match e.kind() {
        io::ErrorKind::NotFound => Probe::Missing,
        io::ErrorKind::PermissionDenied => Probe::Denied,
        _ => Probe::Failed,
    }
}

// libapparmor reads two bytes and looks only at the first.
fn read_param(path: &Path) -> Param {
    let mut f = match File::open(path) {
        Ok(f) => f,
        Err(e) => return Param::Unread(probe_of(&e)),
    };
    let mut b = [0u8; 2];
    match f.read(&mut b) {
        Ok(0) => Param::Unread(Probe::Failed),
        Ok(_) if b[0] == b'Y' => Param::Yes,
        Ok(_) => Param::No,
        Err(e) => Param::Unread(probe_of(&e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profiles_file_is_read_by_its_last_parenthesis() {
        let t = b"a (b) (enforce)\n:ns:x (complain)\n";
        let p = parse_profiles(t).unwrap();
        assert_eq!(p[0].name, b"a (b)");
        assert_eq!(p[0].mode, b"enforce");
        assert_eq!(p[1].name, b":ns:x");
        assert!(parse_profiles(b"x enforce\n").is_err());
    }

    #[test]
    fn attribute_choice_follows_libapparmor() {
        use AttrFile::*;
        let a = |first, fallback| Attempts { first, fallback };
        let all = [
            Param::Yes,
            Param::No,
            Param::Unread(Probe::Missing),
            Param::Unread(Probe::Denied),
        ];
        for av in all {
            assert_eq!(
                choose(Probe::Present, Param::Yes, av),
                a(Some(Stacking), Some(Legacy))
            );
            assert_eq!(
                choose(Probe::Present, Param::No, av),
                a(Some(Stacking), None)
            );
            assert_eq!(
                choose(Probe::Missing, Param::Yes, av),
                a(Some(Legacy), None)
            );
        }
        assert_eq!(
            choose(Probe::Missing, Param::No, Param::Yes),
            a(Some(Stacking), None)
        );
        assert_eq!(choose(Probe::Missing, Param::No, Param::No), a(None, None));
        assert_eq!(
            choose(Probe::Missing, Param::No, Param::Unread(Probe::Missing)),
            a(Some(Legacy), None)
        );
        assert_eq!(
            choose(Probe::Failed, Param::No, Param::Unread(Probe::Missing)),
            a(Some(Stacking), None)
        );
        assert_eq!(
            choose(Probe::Missing, Param::Unread(Probe::Missing), Param::No),
            a(None, Some(Legacy))
        );
        assert_eq!(
            choose(Probe::Missing, Param::Unread(Probe::Denied), Param::No),
            a(Some(Legacy), None)
        );
        assert_eq!(
            choose(Probe::Failed, Param::Unread(Probe::Denied), Param::No),
            a(Some(Stacking), Some(Legacy))
        );
        // A directory policy hides still counts as present.
        assert_eq!(
            choose(Probe::Denied, Param::Unread(Probe::Denied), Param::No),
            a(Some(Stacking), Some(Legacy))
        );
        assert_eq!(
            choose(Probe::Denied, Param::Yes, Param::No),
            a(Some(Legacy), None)
        );
    }

    #[test]
    fn exec_command_is_refused_when_empty_or_with_nul() {
        let at = choose(Probe::Present, Param::Yes, Param::Yes);
        assert!(ExecTransition::with(b"", at).is_err());
        assert!(ExecTransition::with(b"a\0b", at).is_err());
        assert_eq!(ExecTransition::with(b"p", at).unwrap().command, b"exec p");
    }

    #[test]
    fn fqname_puts_the_namespace_in_front() {
        let u = Unit {
            name: b"p//h".to_vec(),
            namespace: Some(b"n".to_vec()),
            data: Vec::new(),
        };
        assert_eq!(fqname(&u), b":n://p//h");
    }
}
