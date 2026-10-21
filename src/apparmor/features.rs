//! Kernel and policy features: the text the kernel publishes under
//! `/sys/kernel/security/apparmor/features`, flattened the way upstream
//! flattens it, and queried the way libapparmor queries it.
//!
//! A feature set is a nested list of names and values in braces, such as
//! `file {mask {create read write}} policy {versions {v7 {yes}}}`. A path
//! like `policy/versions/v7` is supported when each component is found
//! in turn at the right nesting level.

use std::path::Path;

/// The largest feature text accepted, as libapparmor's buffer allows.
pub const MAX_FEATURES: usize = 8192 * 16;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Features {
    text: Vec<u8>,
}

fn is_brace_space_or_nul(c: u8) -> bool {
    c == b'{' || c == b'}' || c.is_ascii_whitespace() || c == 0
}

/// libapparmor's walk_one: finds one path component at the current
/// level, starting at `pos`, which for a nested component must be on its
/// opening brace. Returns where the component's value starts.
fn walk_one(s: &[u8], pos: usize, comp: &[u8], top: bool) -> Option<usize> {
    if comp.is_empty() {
        return None;
    }
    let at = |i: usize| s.get(i).copied().unwrap_or(0);
    let mut cur = pos;
    if !top {
        if at(cur) != b'{' {
            return None;
        }
        cur += 1;
    }
    let mut braces: u32 = 0;
    let mut i = 0;
    while at(cur) != 0 && i < comp.len() {
        let c = at(cur);
        if !c.is_ascii() {
            return None;
        } else if c == b'{' {
            braces = braces.checked_add(1)?;
        } else if c == b'}' {
            if braces == 0 {
                return None;
            }
            braces -= 1;
        }
        if braces == 0 && c == comp[i] {
            i += 1;
        } else {
            i = 0;
        }
        cur += 1;
        if i == comp.len() && !is_brace_space_or_nul(at(cur)) {
            i = 0;
        }
    }
    if i != comp.len() || !is_brace_space_or_nul(at(cur)) {
        return None;
    }
    while at(cur) != 0 && at(cur) != b'{' && at(cur) != b'}' {
        if !at(cur).is_ascii() {
            return None;
        }
        cur += 1;
    }
    Some(cur)
}

impl Features {
    pub fn from_text(text: &[u8]) -> Result<Features, String> {
        if text.len() >= MAX_FEATURES {
            return Err("features text too large".into());
        }
        let end = text.iter().position(|&c| c == 0).unwrap_or(text.len());
        Ok(Features {
            text: text[..end].to_vec(),
        })
    }

    pub fn text(&self) -> &[u8] {
        &self.text
    }

    fn lookup(&self, path: &str) -> Option<usize> {
        if path.is_empty() || path.starts_with('/') {
            return None;
        }
        let comps: Vec<&[u8]> = path
            .as_bytes()
            .split(|&c| c == b'/')
            .filter(|c| !c.is_empty())
            .take(32)
            .collect();
        if comps.is_empty() {
            return None;
        }
        let mut pos = 0;
        for (i, c) in comps.iter().enumerate() {
            pos = walk_one(&self.text, pos, c, i == 0)?;
        }
        Some(pos)
    }

    pub fn supports(&self, path: &str) -> bool {
        self.lookup(path).is_some()
    }

    /// The text of a leaf, such as the capability names of `caps/mask`.
    pub fn value(&self, path: &str) -> Option<Vec<u8>> {
        let mut cur = self.lookup(path)?;
        if self.text.get(cur) != Some(&b'{') {
            return None;
        }
        cur += 1;
        let start = cur;
        while cur < self.text.len() && self.text[cur] != b'{' && self.text[cur] != b'}' {
            if !self.text[cur].is_ascii() {
                return None;
            }
            cur += 1;
        }
        if self.text.get(cur) == Some(&b'{') {
            return None;
        }
        Some(self.text[start..cur].to_vec())
    }

    /// Reads the kernel's feature tree from a directory such as
    /// `/sys/kernel/security/apparmor/features`, flattened as libapparmor
    /// flattens it: entries in name order, each `name {content}\n`.
    pub fn from_dir(dir: &Path) -> std::io::Result<Features> {
        let mut out = Vec::new();
        flatten(dir, &mut out, 0)?;
        Features::from_text(&out).map_err(std::io::Error::other)
    }
}

fn flatten(dir: &Path, out: &mut Vec<u8>, depth: usize) -> std::io::Result<()> {
    use std::io::Read;
    if depth > 16 {
        return Err(std::io::Error::other("features tree too deep"));
    }
    let mut names: Vec<_> = std::fs::read_dir(dir)?
        .filter_map(|e| e.ok())
        .map(|e| e.file_name())
        .collect();
    names.sort();
    for name in names {
        let n = name.as_encoded_bytes();
        if n.is_empty() || n[0] == b'.' {
            continue;
        }
        let path = dir.join(&name);
        let meta = std::fs::metadata(&path)?;
        out.extend_from_slice(n);
        out.extend_from_slice(b" {");
        if meta.is_file() {
            let mut f = std::fs::File::open(&path)?;
            let room = MAX_FEATURES.saturating_sub(out.len());
            f.by_ref().take(room as u64 + 1).read_to_end(out)?;
        } else if meta.is_dir() {
            flatten(&path, out, depth + 1)?;
        }
        out.extend_from_slice(b"}\n");
        if out.len() >= MAX_FEATURES {
            return Err(std::io::Error::other("features text too large"));
        }
    }
    Ok(())
}

/// What upstream assumes for a profile without an `abi` rule when no
/// features were given, byte for byte from its default_features.c. The
/// stray brace after `change_hat` is upstream's: it closes the top level
/// early, so nothing after it, `policy` included, is found in this set.
pub const DEFAULT_ABI: &str = concat!(
    "query {label {multi_transaction {yes}data {yes}perms {allow deny",
    " audit quiet}}}dbus {mask {acquire send receive}}signal {mask {h",
    "up int quit ill trap abrt bus fpe kill usr1 segv usr2 pipe alrm ",
    "term stkflt chld cont stop stp ttin ttou urg xcpu xfsz vtalrm pr",
    "of winch io pwr sys emt lost}}ptrace {mask {read trace}}caps {ma",
    "sk {chown dac_override dac_read_search fowner fsetid kill setgid",
    " setuid setpcap linux_immutable net_bind_service net_broadcast n",
    "et_admin net_raw ipc_lock ipc_owner sys_module sys_rawio sys_chr",
    "oot sys_ptrace sys_pacct sys_admin sys_boot sys_nice sys_resourc",
    "e sys_time sys_tty_config mknod lease audit_write audit_control ",
    "setfcap mac_override mac_admin syslog wake_alarm block_suspend a",
    "udit_read perfmon bpf}}rlimit {mask {cpu fsize data stack core r",
    "ss nproc nofile memlock as locks sigpending msgqueue nice rtprio",
    " rttime}}capability {0xffffff}namespaces {pivot_root {no}profile",
    " {yes}}mount {mask {mount umount pivot_root}}network {af_unix {y",
    "es}af_mask {unspec unix inet ax25 ipx appletalk netrom bridge at",
    "mpvc x25 inet6 rose netbeui security key netlink packet ash econ",
    "et atmsvc rds sna irda pppox wanpipe llc ib mpls can tipc blueto",
    "oth iucv rxrpc isdn phonet ieee802154 caif alg nfc vsock kcm qip",
    "crtr smc xdp}}file {mask {create read write exec append mmap_exe",
    "c link lock}}domain {version {1.2}}computed_longest_left {yes}po",
    "st_nnp_subset {yes}fix_binfmt_elf_mmap {yes}stack {yes}change_pr",
    "ofile {yes}change_onexec {yes}change_hatv {yes}change_hat {yes}}",
    "policy {set_load {yes}versions {v8 {yes}v7 {yes}v6 {yes}v5 {yes}",
    "}}",
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_are_found_at_their_level_only() {
        let f = Features::from_text(
            b"file {mask {create read}} policy {versions {v7 {yes}} set_load {yes}}",
        )
        .unwrap();
        assert!(f.supports("file"));
        assert!(f.supports("file/mask"));
        assert!(f.supports("file/mask/read"));
        assert!(f.supports("policy/versions/v7"));
        assert!(!f.supports("policy/versions/v6"));
        assert!(!f.supports("mask"));
        assert!(!f.supports("file/read"));
        assert!(!f.supports("file/mask/rea"));
        assert_eq!(f.value("file/mask").unwrap(), b"create read".to_vec());
        assert_eq!(f.value("policy/versions"), None);
    }

    #[test]
    fn the_default_abi_hides_what_follows_its_stray_brace() {
        let f = Features::from_text(DEFAULT_ABI.as_bytes()).unwrap();
        assert!(f.supports("file/mask/create"));
        assert!(f.supports("domain/version"));
        assert!(f.supports("stack"));
        assert!(!f.supports("domain/stack"));
        assert!(!f.supports("policy/versions/v7"));
    }
}
