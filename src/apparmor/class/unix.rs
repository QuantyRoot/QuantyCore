//! `unix` rules: upstream's af_unix.cc and the parts of af_rule.cc it
//! uses. A unix rule also stands in, downgraded, as a network rule for
//! the AF_UNIX family.

use super::network::{self, map_perms, Network};
use super::{add_prefix, conds_upstream, hex, pattern, perm_words, Head};
use super::{CLASS_NET, CLASS_NETV8, CLASS_NETV9, DEFAULT};
use crate::apparmor::ast::{Cond, CondList, CondOp, PermWord};
use crate::apparmor::compile::aare::{convert, Glob};
use crate::apparmor::compile::rules::RuleSet;
use crate::apparmor::compile::Support;
use crate::apparmor::model::{Audit, Owner, Prefix, RuleMode};
use crate::apparmor::process::filter_slashes;

pub const AF_UNIX: u32 = 1;
const AUTOBIND: &str = "\\x00[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]";
const CMD_ADDR: u32 = 1;
const CMD_LISTEN: u32 = 2;
const CMD_OPT: u32 = 4;

#[derive(Debug, Clone, Default)]
pub struct Unix {
    pub head: Head,
    pub sock_type: Option<Vec<u8>>,
    pub sock_type_n: i32,
    pub label: Option<Vec<u8>>,
    pub peer_label: Option<Vec<u8>>,
    pub addr: Option<Vec<u8>>,
    pub peer_addr: Option<Vec<u8>>,
    /// Whether generating this rule also adds a network rule for its
    /// family; not for the ones a network rule made.
    pub downgrade: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Side {
    Local,
    Peer,
    Either,
}

struct Supported {
    name: &'static [u8],
    supported: bool,
    side: Side,
}

const BASE: &[Supported] = &[
    Supported {
        name: b"type",
        supported: true,
        side: Side::Local,
    },
    Supported {
        name: b"protocol",
        supported: false,
        side: Side::Local,
    },
    Supported {
        name: b"label",
        supported: true,
        side: Side::Peer,
    },
];

const UNIX: &[Supported] = &[Supported {
    name: b"addr",
    supported: true,
    side: Side::Either,
}];

/// upstream's af_rule::cond_check: whether the table knows the
/// condition, after refusing the ways it can be misused.
fn cond_check(table: &[Supported], c: &Cond, peer: bool, rname: &str) -> Result<bool, String> {
    let name = String::from_utf8_lossy(&c.name);
    for s in table {
        if s.name != &c.name[..] {
            continue;
        }
        if !s.supported {
            return Err(format!(
                "{rname} rule: '{name}' conditional is not currently supported"
            ));
        }
        if !peer && s.side == Side::Peer {
            return Err(format!(
                "{rname} rule: '{name}' conditional is only valid in the peer expression"
            ));
        }
        if peer && s.side == Side::Local {
            return Err(format!(
                "{rname} rule: '{name}' conditional is not allowed in the peer expression"
            ));
        }
        if c.op != CondOp::Eq {
            return Err(format!(
                "{rname} rule: operator used is not allowed in '{name}' socket conditional"
            ));
        }
        if c.values.len() > 1 {
            return Err(format!(
                "{rname} rule: conditional '{name}' only supports a single value"
            ));
        }
        return Ok(true);
    }
    Ok(false)
}

fn take(dst: &mut Option<Vec<u8>>, kind: &str, c: &Cond) -> Result<(), String> {
    super::move_value(kind, dst, c)
}

fn valid_addr(a: &[u8]) -> bool {
    a.first() == Some(&b'@') || a == b"none" || a == b"auto"
}

impl Unix {
    /// upstream's af_rule::move_base_cond.
    fn base_cond(&mut self, c: &Cond, peer: bool) -> Result<bool, String> {
        if !cond_check(BASE, c, peer, "unknown")? {
            return Ok(false);
        }
        match &c.name[..] {
            b"type" => {
                take(&mut self.sock_type, "socket rule", c)?;
                let t = self.sock_type.clone().unwrap_or_default();
                self.sock_type_n = network::type_val(&t);
                if self.sock_type_n == -1 {
                    return Err(format!(
                        "socket rule: invalid socket type '{}'",
                        String::from_utf8_lossy(&t)
                    ));
                }
            }
            b"protocol" => {
                return Err("socket rule: 'protocol' conditional is not currently supported".into())
            }
            b"label" => {
                if peer {
                    take(&mut self.peer_label, "unix", c)?;
                } else {
                    take(&mut self.label, "unix", c)?;
                }
            }
            _ => return Ok(false),
        }
        Ok(true)
    }

    fn conds(&mut self, conds: &[Cond], peer: bool) -> Result<(), String> {
        for c in conds_upstream(conds) {
            if !cond_check(UNIX, c, peer, "unix")? && !self.base_cond(c, peer)? {
                let what = if peer {
                    "peer conditional"
                } else {
                    "conditional"
                };
                return Err(format!(
                    "unix rule: invalid {what} '{}'",
                    String::from_utf8_lossy(&c.name)
                ));
            }
            if c.name == b"addr" {
                let dst = if peer {
                    &mut self.peer_addr
                } else {
                    &mut self.addr
                };
                take(dst, "unix", c)?;
                let a = dst.clone().unwrap_or_default();
                if !valid_addr(&a) {
                    return Err(format!(
                        "unix rule: invalid value for addr='{}'",
                        String::from_utf8_lossy(&a)
                    ));
                }
            }
        }
        Ok(())
    }

    pub fn has_peer_conds(&self) -> bool {
        self.peer_label.is_some() || self.peer_addr.is_some()
    }

    pub fn new(
        perms: &Option<Vec<PermWord>>,
        conds: &[Cond],
        peer: &Option<CondList>,
        prefix: Prefix,
    ) -> Result<Unix, String> {
        let p = perm_words(perms, network::word)?;
        if let Some(l) = peer {
            if l.name != b"peer" {
                return Err(format!(
                    "unix rule: invalid conditional group {}=()",
                    String::from_utf8_lossy(&l.name)
                ));
            }
        }
        let mut r = Unix {
            sock_type_n: -1,
            downgrade: true,
            ..Unix::default()
        };
        r.conds(conds, false)?;
        if let Some(l) = peer {
            r.conds(&l.conds, true)?;
        }
        r.head.perms = if p != 0 {
            if p & !network::VALID != 0 {
                return Err("perms contains invalid permissions for unix socket rules".into());
            } else if p & !network::PEER != 0 && r.has_peer_conds() {
                return Err("unix socket 'create', 'shutdown', 'setattr', 'getattr', 'bind', 'listen', 'setopt', and/or 'getopt' accesses cannot be used with peer socket conditionals".into());
            }
            p
        } else {
            network::VALID
        };
        if prefix.owner != Owner::Unspecified {
            return Err("owner prefix not allowed on unix rules".into());
        }
        r.head.prefix = add_prefix(Prefix::default(), prefix)?;
        Ok(r)
    }

    /// The rule a network rule or an `all` rule implies for AF_UNIX:
    /// all permissions, the given socket type, and the audit and mode
    /// as given, not passed through add_prefix.
    pub fn implied(sock_type: u32, audit: Audit, mode: RuleMode) -> Result<Unix, String> {
        let mut r = Unix {
            sock_type_n: -1,
            ..Unix::default()
        };
        if sock_type != u32::MAX {
            r.sock_type_n = sock_type as i32;
            match network::type_name(sock_type as i32) {
                Some(n) => r.sock_type = Some(n.as_bytes().to_vec()),
                None => {
                    return Err(format!(
                        "socket rule: invalid socket type '{}'",
                        sock_type as i32
                    ))
                }
            }
        }
        r.head.perms = network::VALID;
        r.head.prefix.audit = audit;
        r.head.prefix.mode = mode;
        Ok(r)
    }

    pub fn expand(
        &mut self,
        f: &mut dyn FnMut(&mut Vec<u8>) -> Result<(), String>,
    ) -> Result<(), String> {
        for v in [&mut self.label, &mut self.peer_label, &mut self.addr]
            .into_iter()
            .flatten()
        {
            f(v)?;
        }
        if let Some(a) = self.addr.as_mut() {
            filter_slashes(a);
        }
        if let Some(a) = self.peer_addr.as_mut() {
            f(a)?;
            filter_slashes(a);
        }
        Ok(())
    }

    /// upstream's downgrade_rule: the network rule an allow rule adds
    /// for kernels that mediate sockets only by family and type. A deny
    /// rule adds none, since the coarser rule would deny too much.
    pub fn downgraded(&self) -> Result<Option<Network>, String> {
        if !self.downgrade || self.head.prefix.mode == RuleMode::Deny {
            return Ok(None);
        }
        let mut n = Network::for_family(self.head.perms, AF_UNIX, self.sock_type_n as u32)?;
        let p = Prefix {
            priority: 0,
            audit: self.head.prefix.audit,
            mode: self.head.prefix.mode,
            owner: self.head.prefix.owner,
        };
        n.head.prefix = add_prefix(n.head.prefix, p)?;
        Ok(Some(n))
    }

    /// What upstream's downgrade_rule writes straight into the per
    /// family table before it makes the network rule: the type, or all
    /// types, of AF_UNIX allowed. The table is allocated even for a deny
    /// rule, which adds nothing to it.
    pub fn downgrade_table(&self, table: &mut Option<crate::apparmor::binary::NetTable>) {
        if !self.downgrade {
            return;
        }
        let t = table.get_or_insert_with(|| vec![[0; 4]; network::AF_MAX as usize]);
        if self.head.prefix.mode == RuleMode::Deny {
            return;
        }
        let mask = if self.sock_type_n != -1 {
            1u32.wrapping_shl(self.sock_type_n as u32)
        } else {
            u32::MAX
        };
        t[AF_UNIX as usize][0] |= mask;
        if self.head.prefix.audit == Audit::Force {
            t[AF_UNIX as usize][1] |= mask;
        }
    }

    fn prot(&self, s: &Support) -> String {
        let mut c = if s.networkv8 { CLASS_NETV8 } else { CLASS_NET };
        if s.networkv9 {
            c = CLASS_NETV9;
        }
        let mut b = hex(c);
        b.push_str(&u16_hex(AF_UNIX));
        if self.sock_type.is_some() {
            b.push_str(&u16_hex(self.sock_type_n as u32));
        } else {
            b.push_str("..");
        }
        b.push_str("..");
        b
    }

    pub fn gen(&self, set: &mut RuleSet, s: &Support) -> Result<(), String> {
        if !(s.unixv7 || s.unixv9) {
            return Ok(());
        }
        let h = &self.head;
        let audit = |m: u32| map_perms(if h.prefix.audit == Audit::Force { m } else { 0 });
        let add =
            |set: &mut RuleSet, re: &str, perms: u32, audit: u32| h.add(set, re, perms, audit);
        let mut buffer = self.prot(s);
        let mut mask = h.perms;
        let peer = self.has_peer_conds();
        if mask & network::CREATE != 0 && !peer {
            add(
                set,
                &buffer,
                map_perms(network::CREATE),
                audit(network::CREATE),
            )?;
            mask &= !network::CREATE;
        }
        let auto = self.addr.as_deref() == Some(b"auto");
        if mask & network::BIND != 0 && (self.addr.is_none() || auto) {
            let mut tmp = buffer.clone();
            tmp.push_str("\\x00");
            tmp.push_str(&label_pattern(&self.label)?);
            tmp.push_str("\\x00");
            add(set, &tmp, map_perms(network::BIND), audit(network::BIND))?;
            if self.addr.is_some() {
                mask &= !network::BIND;
            }
        }
        if mask != 0 {
            buffer.push_str(&addr_pattern(&self.addr)?);
            buffer.push_str(&label_pattern(&self.label)?);
            buffer.push_str("\\x00");
            let local = if peer {
                network::ACCEPT
            } else {
                network::LOCAL & !network::LOCAL_CMD
            };
            if mask & local != 0 {
                add(set, &buffer, map_perms(mask & local), audit(mask & local))?;
            }
            if mask & network::LISTEN != 0 && !peer {
                let re = format!("{buffer}{}..", hex(CMD_LISTEN));
                add(set, &re, map_perms(network::LISTEN), audit(network::LISTEN))?;
            }
            if mask & network::OPT != 0 && !peer {
                let re = format!("{buffer}{}..", hex(CMD_OPT));
                add(
                    set,
                    &re,
                    map_perms(mask & network::OPT),
                    audit(network::OPT),
                )?;
            }
            mask &= !network::LOCAL | network::ACCEPT;
        }
        if mask & network::PEER != 0 {
            buffer.push_str(&hex(CMD_ADDR));
            buffer.push_str(&addr_pattern(&self.peer_addr)?);
            buffer.push_str(&label_pattern(&self.peer_label)?);
            add(
                set,
                &buffer,
                map_perms(h.perms & network::PEER),
                audit(h.perms & network::PEER),
            )?;
        }
        Ok(())
    }
}

/// Two bytes, big endian, as `\xNN\xNN`.
pub fn u16_hex(v: u32) -> String {
    let b = (v as u16).to_be_bytes();
    format!("{}{}", hex(b[0] as u32), hex(b[1] as u32))
}

fn addr_pattern(addr: &Option<Vec<u8>>) -> Result<String, String> {
    let mut out = match addr.as_deref() {
        Some(b"none") => "\\x01".to_string(),
        Some(b"auto") => AUTOBIND.to_string(),
        Some(a) => {
            let mut buf = Vec::new();
            convert(a.get(1..).unwrap_or_default(), Glob::Null, &mut buf)
                .map_err(|_| format!("Invalid unix address '{}'", String::from_utf8_lossy(a)))?;
            format!("\\x00{}", String::from_utf8_lossy(&buf))
        }
        None => ".*".to_string(),
    };
    out.push_str("\\x00");
    Ok(out)
}

fn label_pattern(label: &Option<Vec<u8>>) -> Result<String, String> {
    match label {
        Some(l) => pattern(l),
        None => Ok(DEFAULT.to_string()),
    }
}
