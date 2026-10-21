//! The profile Kubernetes means by `RuntimeDefault`: containerd's default
//! container profile, rendered as containerd renders it and compiled here.
//!
//! The rules are containerd's `contrib/apparmor/template.go` at commit
//! 926009266892, Copyright The containerd Authors, licensed under the
//! Apache License, Version 2.0. Why containerd's and not CRI-O's or
//! Docker's, which differ in a few rules: ADR-038.

use super::model::Policy;
use super::source::{Error, Opened, Resolver};
use super::Options;

/// The name containerd's CRI plugin gives the profile.
pub const NAME: &str = "cri-containerd.apparmor.d";

/// The inputs of containerd's template, field for field.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeDefault {
    /// `abi/3.0` when the host has it, so the profile means on a newer
    /// kernel what it meant when it was written.
    pub abi: Option<String>,
    pub name: String,
    /// Lines before the profile: the host's tunables, or a definition of
    /// `@{PROC}` when there are none.
    pub imports: Vec<String>,
    /// Lines inside the profile: the host's base abstraction, if any.
    pub inner_imports: Vec<String>,
    /// The profile confining the runtime, which may signal containers.
    pub daemon_profile: String,
    /// The path of rootlesskit, when one is installed.
    pub rootless_kit: Option<String>,
}

impl RuntimeDefault {
    /// The profile on a host without `/etc/apparmor.d`: nothing included,
    /// so it compiles the same everywhere. The daemon is unconfined.
    pub fn bare(name: &str) -> RuntimeDefault {
        RuntimeDefault {
            abi: None,
            name: name.to_string(),
            imports: vec!["@{PROC}=/proc/".to_string()],
            inner_imports: Vec::new(),
            daemon_profile: "unconfined".to_string(),
            rootless_kit: None,
        }
    }

    /// The profile as containerd renders it on a host, which it asks
    /// whether `abi/3.0`, `tunables/global` and `abstractions/base` exist
    /// in the profile directory. `current` is the runtime's own
    /// `/proc/self/attr/current`, or None when it could not be read.
    pub fn for_host(
        resolver: &mut dyn Resolver,
        name: &str,
        current: Option<&[u8]>,
    ) -> RuntimeDefault {
        let mut exists = |m: &str| {
            let dirs = resolver.search_path().to_vec();
            dirs.iter().any(|d| {
                let mut p = d.clone();
                p.push(b'/');
                p.extend_from_slice(m.as_bytes());
                !matches!(resolver.open(&p), Opened::NotFound)
            })
        };
        let mut r = RuntimeDefault::bare(name);
        if exists("abi/3.0") {
            r.abi = Some("abi/3.0".to_string());
        }
        if exists("tunables/global") {
            r.imports = vec!["#include <tunables/global>".to_string()];
        }
        if exists("abstractions/base") {
            r.inner_imports = vec!["#include <abstractions/base>".to_string()];
        }
        r.daemon_profile = daemon_profile(current.unwrap_or(b""));
        r
    }

    /// The profile text, byte for byte what containerd's template gives.
    /// The fields go in unescaped, as containerd puts them in; a name from
    /// an untrusted source can add rules of its own.
    pub fn render(&self) -> String {
        let mut s = String::from("\n");
        if let Some(abi) = &self.abi {
            if !abi.is_empty() {
                s.push_str(&format!("abi <{abi}>,\n"));
            }
        }
        s.push('\n');
        for i in &self.imports {
            s.push_str(&format!("\n{i}\n"));
        }
        let name = &self.name;
        s.push_str(&format!(
            "\n\nprofile {name} flags=(attach_disconnected,mediate_deleted) {{\n"
        ));
        for i in &self.inner_imports {
            s.push_str(&format!("\n  {i}\n"));
        }
        s.push('\n');
        s.push_str(HEAD);
        s.push_str(&format!(
            "  signal (receive) peer={},\n",
            self.daemon_profile
        ));
        s.push_str("  # Container processes may send signals amongst themselves.\n");
        s.push_str(&format!("  signal (send,receive) peer={name},\n"));
        if let Some(rk) = self.rootless_kit.as_deref().filter(|r| !r.is_empty()) {
            s.push_str("\n  # https://github.com/containerd/nerdctl/issues/2730\n");
            s.push_str(&format!("  signal (receive) peer={rk},\n"));
        }
        s.push('\n');
        s.push_str(DENY);
        s.push_str(&format!(
            "  ptrace (trace,tracedby,read,readby) peer={name},\n}}\n"
        ));
        s
    }

    /// Renders and compiles the profile; `resolver` supplies what the
    /// includes name, if there are any.
    pub fn compile(&self, resolver: &mut dyn Resolver, opts: &Options) -> Result<Policy, Error> {
        super::compile(resolver, &self.name, self.render().into_bytes(), opts)
    }
}

/// containerd's cleanProfileName: the label up to its first space, and
/// `unconfined` for none. Profile names cannot hold spaces, so this drops
/// only the mode.
pub fn daemon_profile(current: &[u8]) -> String {
    let s = String::from_utf8_lossy(current);
    let first = s.split(' ').next().unwrap_or("");
    if first.is_empty() {
        "unconfined".to_string()
    } else {
        first.to_string()
    }
}

const HEAD: &str = "
  network,
  capability,
  file,
  umount,
  # Host (privileged) processes may send signals to container processes.
  signal (receive) peer=unconfined,
  # runc may send signals to container processes.
  signal (receive) peer=runc,
  # crun may send signals to container processes.
  signal (receive) peer=crun,
  # Manager may send signals to container processes.
";

const DENY: &str = "
  deny @{PROC}/* w,   # deny write for all files directly in /proc (not in a subdir)
  # deny write to files not in /proc/<number>/** or /proc/sys/**
  deny @{PROC}/{[^1-9],[^1-9][^0-9],[^1-9s][^0-9y][^0-9s],[^1-9][^0-9][^0-9][^0-9]*}/** w,
  deny @{PROC}/sys/[^k]** w,  # deny /proc/sys except /proc/sys/k* (effectively /proc/sys/kernel)
  deny @{PROC}/sys/kernel/{?,??,[^s][^h][^m]**} w,  # deny everything except shm* in /proc/sys/kernel/
  deny @{PROC}/sysrq-trigger rwklx,
  deny @{PROC}/mem rwklx,
  deny @{PROC}/kmem rwklx,
  deny @{PROC}/kcore rwklx,

  deny mount,

  deny /sys/[^f]*/** wklx,
  deny /sys/f[^s]*/** wklx,
  deny /sys/fs/[^c]*/** wklx,
  deny /sys/fs/c[^g]*/** wklx,
  deny /sys/fs/cg[^r]*/** wklx,
  deny /sys/firmware/** rwklx,
  deny /sys/devices/virtual/powercap/** rwklx,
  deny /sys/kernel/security/** rwklx,

  # allow processes within the container to trace each other,
  # provided all other LSM and yama setting allow it.
";

#[cfg(test)]
mod tests {
    use super::*;
    use crate::apparmor::MemResolver;

    #[test]
    fn bare_profile_compiles_without_any_file() {
        let r = RuntimeDefault::bare(NAME);
        let p = r
            .compile(&mut MemResolver::default(), &Options::default())
            .unwrap();
        assert_eq!(p.profiles.len(), 1);
        assert!(r.render().starts_with("\n\n\n@{PROC}=/proc/\n\n\nprofile "));
    }

    #[test]
    fn daemon_profile_drops_the_mode() {
        assert_eq!(daemon_profile(b"containerd (enforce)\n"), "containerd");
        assert_eq!(daemon_profile(b""), "unconfined");
        // The kernel ends the label with a newline, which containerd keeps;
        // the parser takes it as the space before the comma.
        assert_eq!(daemon_profile(b"unconfined\n"), "unconfined\n");
    }
}
