//! `network` rules: upstream's network.cc. Families and socket types
//! come from its tables; addresses, ports, interfaces and labels are
//! encoded for kernels with fine grained inet mediation.

use std::collections::BTreeMap;
use std::sync::OnceLock;

use super::unix::AF_UNIX;
use super::{add_prefix, conds_upstream, hex, move_value, pattern, perm_words, x_perms, Head};
use super::{CLASS_NETV8, CLASS_NETV9, CLASS_NETV9_SKB, DEFAULT};
use crate::apparmor::ast::{Cond, CondList, CondOp, PermWord};
use crate::apparmor::compile::rules::RuleSet;
use crate::apparmor::compile::Support;
use crate::apparmor::lexer::T;
use crate::apparmor::model::{Audit, Owner, Prefix};

pub const SEND: u32 = 0x0002;
pub const RECEIVE: u32 = 0x0004;
pub const CREATE: u32 = 0x0010;
pub const SHUTDOWN: u32 = 0x0020;
pub const CONNECT: u32 = 0x0040;
pub const SETATTR: u32 = 0x0100;
pub const GETATTR: u32 = 0x0200;
pub const ACCEPT: u32 = 0x0010_0000;
pub const BIND: u32 = 0x0020_0000;
pub const LISTEN: u32 = 0x0040_0000;
pub const SETOPT: u32 = 0x0100_0000;
pub const GETOPT: u32 = 0x0200_0000;
pub const CONT_MATCH: u32 = 0x0800_0000;
pub const COMPAT_CONT_MATCH: u32 = CONT_MATCH << 1;
pub const SET_LABEL: u32 = 0x8000_0000;
pub const VALID: u32 = SEND
    | RECEIVE
    | CREATE
    | SHUTDOWN
    | CONNECT
    | SETATTR
    | GETATTR
    | BIND
    | ACCEPT
    | LISTEN
    | SETOPT
    | GETOPT
    | SET_LABEL
    | CONT_MATCH;
pub const LOCAL: u32 =
    CREATE | SHUTDOWN | SETATTR | GETATTR | BIND | ACCEPT | LISTEN | SETOPT | GETOPT;
pub const OPT: u32 = SETOPT | GETOPT;
pub const LOCAL_CMD: u32 = LISTEN | OPT;
pub const PEER: u32 = VALID & (!LOCAL | ACCEPT);

const AF_INET: u32 = 2;
const AF_INET6: u32 = 10;
/// AF_MAX of upstream's base_af_names.h at the pinned commit.
pub const AF_MAX: u32 = 46;
const SOCK_PACKET: u32 = 10;
const ALL_TYPES: u32 = 0x43e;
const CMD_ADDR: u32 = 1;
const CMD_LISTEN: u32 = 2;
const CMD_OPT: u32 = 4;
const IPPORT_RESERVED: u16 = 1024;

/// upstream's map_perms: socket permissions moved to where the kernel
/// checks them in the policy automaton.
pub fn map_perms(mask: u32) -> u32 {
    (mask & 0x7f)
        | ((mask & (GETATTR | SETATTR)) << 6)
        | ((mask & (ACCEPT | BIND | LISTEN)) >> 4)
        | ((mask & (SETOPT | GETOPT)) >> 5)
}

const SOCK_TYPES: &[(&str, i32)] = &[
    ("none", 0),
    ("stream", 1),
    ("dgram", 2),
    ("raw", 3),
    ("rdm", 4),
    ("seqpacket", 5),
    ("dccp", 6),
    ("invalid", -1),
    ("invalid", -1),
    ("invalid", -1),
    ("packet", 10),
];

pub fn type_val(name: &[u8]) -> i32 {
    SOCK_TYPES
        .iter()
        .find(|(n, _)| n.as_bytes() == name)
        .map_or(-1, |&(_, v)| v)
}

pub fn type_name(v: i32) -> Option<&'static str> {
    SOCK_TYPES.iter().find(|&&(_, t)| t == v).map(|&(n, _)| n)
}

/// upstream's base_af_names.h.
const FAMILIES: &[(&str, u32)] = &[
    ("unspec", 0),
    ("unix", 1),
    ("inet", 2),
    ("ax25", 3),
    ("ipx", 4),
    ("appletalk", 5),
    ("netrom", 6),
    ("bridge", 7),
    ("atmpvc", 8),
    ("x25", 9),
    ("inet6", 10),
    ("rose", 11),
    ("netbeui", 13),
    ("security", 14),
    ("key", 15),
    ("netlink", 16),
    ("packet", 17),
    ("ash", 18),
    ("econet", 19),
    ("atmsvc", 20),
    ("rds", 21),
    ("sna", 22),
    ("irda", 23),
    ("pppox", 24),
    ("wanpipe", 25),
    ("llc", 26),
    ("ib", 27),
    ("mpls", 28),
    ("can", 29),
    ("tipc", 30),
    ("bluetooth", 31),
    ("iucv", 32),
    ("rxrpc", 33),
    ("isdn", 34),
    ("phonet", 35),
    ("ieee802154", 36),
    ("caif", 37),
    ("alg", 38),
    ("nfc", 39),
    ("vsock", 40),
    ("kcm", 41),
    ("qipcrtr", 42),
    ("smc", 43),
    ("xdp", 44),
    ("mctp", 45),
];

struct Tuple {
    family_name: &'static str,
    family: u32,
    type_name: &'static str,
    sock_type: u32,
    protocol_name: &'static str,
    protocol: u32,
}

/// upstream's network_mappings: six socket types for every family, then
/// the protocol names it maps.
fn mappings() -> &'static [Tuple] {
    static M: OnceLock<Vec<Tuple>> = OnceLock::new();
    M.get_or_init(|| {
        let mut v = Vec::new();
        for &(name, af) in FAMILIES {
            for (t, n) in [
                ("stream", 1),
                ("dgram", 2),
                ("seqpacket", 5),
                ("rdm", 4),
                ("raw", 3),
                ("packet", 10),
            ] {
                v.push(Tuple {
                    family_name: name,
                    family: af,
                    type_name: t,
                    sock_type: n,
                    protocol_name: "",
                    protocol: 0xff_ffff,
                });
            }
        }
        let mapped: [(&str, u32, &str, u32, &str, u32); 8] = [
            ("inet", AF_INET, "raw", 3, "tcp", 1 << 6),
            ("inet", AF_INET, "raw", 3, "udp", 1 << 17),
            ("inet", AF_INET, "raw", 3, "icmp", 1 << 1),
            ("inet", AF_INET, "tcp", 1, "", 0xffff_ffff),
            ("inet", AF_INET, "udp", 2, "", 0xffff_ffff),
            ("inet", AF_INET, "icmp", 3, "", 1 << 1),
            ("inet6", AF_INET6, "tcp", 1, "", 0xffff_ffff),
            ("inet6", AF_INET6, "udp", 2, "", 0xffff_ffff),
        ];
        for (fname, af, tname, t, pname, p) in mapped {
            v.push(Tuple {
                family_name: fname,
                family: af,
                type_name: tname,
                sock_type: t,
                protocol_name: pname,
                protocol: p,
            });
        }
        v
    })
}

/// upstream's net_find_mapping, as an iterator over all matches.
fn find<'a>(
    family: Option<&'a [u8]>,
    ty: Option<&'a [u8]>,
    protocol: Option<&'a [u8]>,
) -> impl Iterator<Item = &'static Tuple> + 'a {
    mappings().iter().filter(move |m| {
        if let Some(f) = family {
            if f != m.family_name.as_bytes() {
                return false;
            }
        }
        if let Some(t) = ty {
            if t != m.type_name.as_bytes() {
                return false;
            }
        }
        if let Some(p) = protocol {
            if ty.is_none() && p == m.type_name.as_bytes() {
                return true;
            }
            if p != m.protocol_name.as_bytes() {
                return false;
            }
        }
        true
    })
}

pub fn word(w: &PermWord) -> Result<u32, String> {
    Ok(match (w.t, &w.text[..]) {
        (T::Create, _) => CREATE,
        (T::Bind, _) => BIND,
        (T::Listen, _) => LISTEN,
        (T::Accept, _) => ACCEPT,
        (T::Connect, _) => CONNECT,
        (T::Shutdown, _) => SHUTDOWN,
        (T::GetAttr, _) => GETATTR,
        (T::SetAttr, _) => SETATTR,
        (T::GetOpt, _) => GETOPT,
        (T::SetOpt, _) => SETOPT,
        (T::Send, _) | (T::Write, _) => SEND,
        (T::Receive, _) | (T::Read, _) => RECEIVE,
        (T::Mode, m) => x_perms("unix", VALID, m)?,
        (T::Value, v) => match v {
            b"create" => CREATE,
            b"bind" => BIND,
            b"listen" => LISTEN,
            b"accept" => ACCEPT,
            b"connect" => CONNECT,
            b"shutdown" => SHUTDOWN,
            b"getattr" => GETATTR,
            b"setattr" => SETATTR,
            b"getopt" => GETOPT,
            b"setopt" => SETOPT,
            b"send" | b"write" => SEND,
            b"receive" | b"read" => RECEIVE,
            m => x_perms("net", VALID, m)?,
        },
        _ => 0,
    })
}

#[derive(Debug, Clone, Default)]
pub struct IpConds {
    pub sip: Option<Vec<u8>>,
    pub sport: Option<Vec<u8>>,
    pub iface: Option<Vec<u8>>,
    pub label_match: Option<Vec<u8>>,
    pub set_label: bool,
    pub is_ip: bool,
    pub is_port: bool,
    pub from_port: u16,
    pub to_port: u16,
    /// The address, network byte order: 4 bytes for IPv4, 16 for IPv6.
    pub ip: Vec<u8>,
    pub is_none: bool,
}

#[derive(Debug, Clone, Default)]
pub struct Network {
    pub head: Head,
    /// Family to (socket type mask, protocol mask), as upstream's
    /// network_perms.
    pub perms_map: BTreeMap<u32, (u32, u32)>,
    /// Family to its (type, protocol) entries, as upstream's
    /// network_map.
    pub entries: BTreeMap<u32, Vec<(u32, u32)>>,
    pub local: IpConds,
    pub peer: IpConds,
}

/// `strtoul(s, &end, 10)` with the checks of upstream's
/// parse_port_number.
fn port_number(s: &[u8]) -> Option<u16> {
    let mut i = 0;
    while i < s.len() && (s[i] == b' ' || (9..=13).contains(&s[i])) {
        i += 1;
    }
    let mut neg = false;
    if i < s.len() && (s[i] == b'+' || s[i] == b'-') {
        neg = s[i] == b'-';
        i += 1;
    }
    let start = i;
    let mut v: u64 = 0;
    let mut overflow = false;
    while i < s.len() && s[i].is_ascii_digit() {
        match v
            .checked_mul(10)
            .and_then(|x| x.checked_add((s[i] - b'0') as u64))
        {
            Some(x) => v = x,
            None => overflow = true,
        }
        i += 1;
    }
    if i == start || i != s.len() {
        return None;
    }
    let v = if overflow {
        u64::MAX
    } else if neg {
        v.wrapping_neg()
    } else {
        v
    };
    u16::try_from(v).ok()
}

fn parse_port(c: &mut IpConds) -> bool {
    c.is_port = true;
    let s = c.sport.clone().unwrap_or_default();
    if let Some(d) = s.iter().position(|&b| b == b'-') {
        if let (Some(f), Some(t)) = (port_number(&s[..d]), port_number(&s[d + 1..])) {
            if f <= t {
                c.from_port = f;
                c.to_port = t;
                return true;
            }
        }
    }
    match port_number(&s) {
        Some(p) => {
            c.from_port = p;
            c.to_port = p;
            true
        }
        None => false,
    }
}

/// glibc's inet_pton for AF_INET: four decimal parts, no leading zeros.
fn pton4(s: &[u8]) -> Option<[u8; 4]> {
    let mut out = [0u8; 4];
    let mut octets = 0;
    let mut saw_digit = false;
    let mut cur: u32 = 0;
    for &c in s {
        if c.is_ascii_digit() {
            if saw_digit && cur == 0 {
                return None;
            }
            cur = cur * 10 + (c - b'0') as u32;
            if cur > 255 {
                return None;
            }
            if !saw_digit {
                octets += 1;
                if octets > 4 {
                    return None;
                }
                saw_digit = true;
            }
            out[octets - 1] = cur as u8;
        } else if c == b'.' && saw_digit {
            if octets == 4 {
                return None;
            }
            cur = 0;
            saw_digit = false;
        } else {
            return None;
        }
    }
    (octets == 4 && saw_digit).then_some(out)
}

/// glibc's inet_pton for AF_INET6.
fn pton6(s: &[u8]) -> Option<[u8; 16]> {
    let mut out = [0u8; 16];
    let mut tp = 0usize;
    let mut colonp: Option<usize> = None;
    let mut i = 0;
    if s.first() == Some(&b':') {
        if s.get(1) != Some(&b':') {
            return None;
        }
        i = 1;
    }
    let mut curtok = i;
    let mut xdigits_seen = 0;
    let mut val: u32 = 0;
    while i < s.len() {
        let ch = s[i];
        i += 1;
        if let Some(d) = (ch as char).to_digit(16) {
            if xdigits_seen == 4 {
                return None;
            }
            val = (val << 4) | d;
            if val > 0xffff {
                return None;
            }
            xdigits_seen += 1;
            continue;
        }
        if ch == b':' {
            curtok = i;
            if xdigits_seen == 0 {
                if colonp.is_some() {
                    return None;
                }
                colonp = Some(tp);
                continue;
            } else if i >= s.len() {
                return None;
            }
            if tp + 2 > 16 {
                return None;
            }
            out[tp] = (val >> 8) as u8;
            out[tp + 1] = val as u8;
            tp += 2;
            xdigits_seen = 0;
            val = 0;
            continue;
        }
        if ch == b'.' && tp + 4 <= 16 {
            let v4 = pton4(&s[curtok..])?;
            out[tp..tp + 4].copy_from_slice(&v4);
            tp += 4;
            xdigits_seen = 0;
            break;
        }
        return None;
    }
    if xdigits_seen > 0 {
        if tp + 2 > 16 {
            return None;
        }
        out[tp] = (val >> 8) as u8;
        out[tp + 1] = val as u8;
        tp += 2;
    }
    if let Some(c) = colonp {
        if tp == 16 {
            return None;
        }
        let n = tp - c;
        for k in 1..=n {
            out[16 - k] = out[c + n - k];
            out[c + n - k] = 0;
        }
        tp = 16;
    }
    (tp == 16).then_some(out)
}

fn parse_address(c: &mut IpConds) -> bool {
    let s = c.sip.clone().unwrap_or_default();
    if s == b"none" {
        c.is_none = true;
        return true;
    }
    c.is_ip = true;
    if let Some(a) = pton6(&s) {
        c.ip = a.to_vec();
        return true;
    }
    if let Some(a) = pton4(&s) {
        c.ip = a.to_vec();
        return true;
    }
    false
}

fn move_conds(conds: &[Cond], c: &mut IpConds) -> Result<(), String> {
    for e in conds_upstream(conds) {
        let shown = String::from_utf8_lossy(&e.name).into_owned();
        if e.name == b"label" {
            move_value("network", &mut c.label_match, e)?;
            match e.op {
                CondOp::Set => c.set_label = true,
                CondOp::Eq => c.set_label = false,
                _ => {
                    return Err("unsupported operator in label conditional of network rules".into())
                }
            }
        } else if e.op != CondOp::Eq {
            return Err("unsupported operator used in conditions of network rules".into());
        } else if e.name == b"ip" {
            move_value("network", &mut c.sip, e)?;
            if !parse_address(c) {
                return Err(format!(
                    "network invalid ip='{}'",
                    String::from_utf8_lossy(c.sip.as_deref().unwrap_or_default())
                ));
            }
        } else if e.name == b"port" {
            move_value("network", &mut c.sport, e)?;
            if !parse_port(c) {
                return Err(format!(
                    "network invalid port='{}'",
                    String::from_utf8_lossy(c.sport.as_deref().unwrap_or_default())
                ));
            }
        } else if e.name == b"interface" {
            move_value("network", &mut c.iface, e)?;
            pattern(c.iface.as_deref().unwrap_or_default()).map_err(|_| {
                format!(
                    "network invalid interface='{}'",
                    String::from_utf8_lossy(c.iface.as_deref().unwrap_or_default())
                )
            })?;
        } else {
            return Err(format!("invalid network rule conditional \"{shown}\""));
        }
    }
    Ok(())
}

fn byte(v: u32) -> String {
    hex(v & 0xff)
}

fn byte_range(from: u32, to: u32) -> String {
    if from == 0 && to == 255 {
        return ".".into();
    }
    format!("[{}-{}]", byte(from), byte(to))
}

fn port_cond(from: u16, to: u16) -> String {
    let (from, to) = (from as u32, to as u32);
    let (fh, th) = (from >> 8, to >> 8);
    if from == to {
        return if from != 0 {
            format!("{}{}", byte(fh), byte(from))
        } else {
            "..".into()
        };
    }
    if fh == th {
        return format!("{}{}", byte(fh), byte_range(from & 0xff, to & 0xff));
    }
    let mut s = format!("({}{}|", byte(fh), byte_range(from & 0xff, 0xff));
    if th - fh > 1 {
        s.push_str(&byte_range(fh + 1, th - 1));
        s.push_str(".|");
    }
    s.push_str(&byte(th));
    s.push_str(&byte_range(0, to & 0xff));
    s.push(')');
    s
}

const PRIVILEGED: &str = "\\x01";
const REMOTE: &str = "\\x02";
const UNPRIVILEGED: &str = "\\x00";

fn port_auto(c: &IpConds, is_peer: bool, is_bind: bool) -> String {
    if is_peer {
        format!("{REMOTE}{}", port_cond(c.from_port, c.to_port))
    } else if is_bind && c.from_port < IPPORT_RESERVED {
        let mut s = String::new();
        let both = c.to_port >= IPPORT_RESERVED;
        let to = if both {
            s.push('(');
            s.push_str(UNPRIVILEGED);
            s.push_str(&port_cond(IPPORT_RESERVED, c.to_port));
            s.push('|');
            IPPORT_RESERVED - 1
        } else {
            c.to_port
        };
        s.push_str(PRIVILEGED);
        s.push_str(&port_cond(c.from_port, to));
        if both {
            s.push(')');
        }
        s
    } else {
        format!("{UNPRIVILEGED}{}", port_cond(c.from_port, c.to_port))
    }
}

fn ip_cond(ip: &[u8]) -> String {
    let mut s = hex(if ip.len() == 4 { 1 } else { 2 });
    for b in ip {
        s.push_str(&hex(*b as u32));
    }
    s
}

fn default_cond(v: &Option<Vec<u8>>, name: &str) -> Result<String, String> {
    match v {
        Some(v) => pattern(v).map_err(|_| format!("Invalidate conditional {name}")),
        None => Ok(DEFAULT.into()),
    }
}

impl Network {
    fn set_perm(&mut self, family: u32, ty: u32, protocol: u32) {
        let e = self.perms_map.entry(family).or_insert((0, 0));
        if ty > SOCK_PACKET {
            e.0 |= ty;
        } else {
            e.0 |= 1 << ty;
        }
        e.1 |= protocol;
    }

    fn push(&mut self, family: u32, ty: u32, protocol: u32) {
        self.entries.entry(family).or_default().push((ty, protocol));
        self.set_perm(family, ty, protocol);
    }

    fn has_local(&self) -> bool {
        self.local.sip.is_some()
            || self.local.sport.is_some()
            || self.local.iface.is_some()
            || self.local.label_match.is_some()
    }

    fn has_peer(&self) -> bool {
        self.peer.sip.is_some() || self.peer.sport.is_some()
    }

    fn check_perms(&mut self, p: u32) -> Result<(), String> {
        self.head.perms = if p != 0 {
            if p & !VALID != 0 {
                return Err("perms contains invalid permissions for network rules".into());
            } else if p & !PEER != 0 && self.has_peer() {
                return Err("network 'create', 'shutdown', 'setattr', 'getattr', 'bind', 'listen', 'setopt', and/or 'getopt' accesses cannot be used with peer socket conditionals".into());
            }
            p
        } else {
            VALID
        };
        Ok(())
    }

    /// The rule as written, before its prefix.
    pub fn parse(
        perms: u32,
        words: &[Vec<u8>],
        conds: &[Cond],
        peer: &Option<CondList>,
    ) -> Result<Network, String> {
        if let Some(l) = peer {
            if l.name != b"peer" {
                return Err(format!(
                    "network rule: invalid conditional group {}=()",
                    String::from_utf8_lossy(&l.name)
                ));
            }
        }
        let mut r = Network::default();
        move_conds(conds, &mut r.local)?;
        if let Some(l) = peer {
            move_conds(&l.conds, &mut r.peer)?;
        }
        if r.peer.iface.is_some() {
            return Err("interface cannot be set for peer in network rules".into());
        }
        r.peer.iface = r.local.iface.clone();
        let conds = r.has_local() || r.has_peer();
        if words.is_empty() {
            if conds {
                for f in [&b"inet"[..], b"inet6"] {
                    for m in find(Some(f), None, None) {
                        r.push(m.family, m.sock_type, m.protocol);
                    }
                }
            } else {
                for f in 0..AF_MAX {
                    r.push(f, u32::MAX, u32::MAX);
                }
            }
        } else {
            let family = Some(&words[0][..]);
            let ty = words.get(1).map(|v| &v[..]);
            for m in find(family, ty, None) {
                if conds && m.family != AF_INET && m.family != AF_INET6 {
                    return Err("network family does not support local or peer conditionals".into());
                }
                r.push(m.family, m.sock_type, m.protocol);
            }
            if ty.is_none() && r.entries.is_empty() {
                // A single word that is no family is read as a type in
                // any family: `network tcp,`.
                for m in find(None, family, None) {
                    if conds && m.family != AF_INET && m.family != AF_INET6 {
                        continue;
                    }
                    r.push(m.family, m.sock_type, m.protocol);
                }
            }
            if r.entries.is_empty() {
                return Err("Invalid network entry.".into());
            }
        }
        r.check_perms(perms)?;
        Ok(r)
    }

    pub fn new(
        perms: &Option<Vec<PermWord>>,
        words: &[Vec<u8>],
        conds: &[Cond],
        peer: &Option<CondList>,
        prefix: Prefix,
    ) -> Result<Network, String> {
        let p = perm_words(perms, word)?;
        let mut r = Network::parse(p, words, conds, peer)?;
        r.add_prefix(prefix)?;
        Ok(r)
    }

    pub fn add_prefix(&mut self, p: Prefix) -> Result<(), String> {
        if p.priority != 0 {
            return Err("priority prefix not allowed on network rules".into());
        }
        if p.owner != Owner::Unspecified {
            return Err("owner prefix not allowed on network rules".into());
        }
        self.head.prefix = add_prefix(self.head.prefix, p)?;
        Ok(())
    }

    /// The single family and type rule a downgraded unix rule adds.
    pub fn for_family(perms: u32, family: u32, ty: u32) -> Result<Network, String> {
        let mut r = Network::default();
        r.push(family, ty, u32::MAX);
        r.check_perms(perms)?;
        Ok(r)
    }

    /// The socket types of AF_UNIX this rule names, for the unix rules
    /// upstream's grammar adds beside it.
    pub fn unix_types(&self) -> Vec<u32> {
        self.entries
            .get(&AF_UNIX)
            .map(|v| v.iter().map(|&(t, _)| t).collect())
            .unwrap_or_default()
    }

    /// upstream's update_compat_net: this rule's families and types in
    /// the per family table, allocated on first use.
    pub fn update_compat(&self, table: &mut Option<crate::apparmor::binary::NetTable>) {
        let t = table.get_or_insert_with(|| vec![[0; 4]; AF_MAX as usize]);
        let deny = self.head.prefix.mode == crate::apparmor::model::RuleMode::Deny;
        let audit = self.head.prefix.audit == Audit::Force;
        for (&family, list) in &self.entries {
            let Some(e) = t.get_mut(family as usize) else {
                continue;
            };
            for &(ty, _) in list {
                let bits = if ty > SOCK_PACKET { ty } else { 1 << ty };
                if deny {
                    e[2] |= bits;
                    if !audit {
                        e[3] |= bits;
                    }
                } else {
                    e[0] |= bits;
                    if audit {
                        e[1] |= bits;
                    }
                }
            }
        }
    }

    fn audit(&self, m: u32) -> u32 {
        if self.head.prefix.audit == Audit::Force {
            map_perms(m)
        } else {
            0
        }
    }

    fn rule(&self, set: &mut RuleSet, re: &str, perms: u32, audit: u32) -> Result<(), String> {
        self.head.add(set, re, perms, audit)
    }

    fn ip_conds(
        &self,
        set: &mut RuleSet,
        streams: &mut Vec<String>,
        entry: &IpConds,
        is_peer: bool,
        is_cmd: bool,
        is_iface: bool,
    ) -> Result<(), String> {
        let perms = self.head.perms;
        for s in streams.iter_mut() {
            if entry.is_port {
                s.push_str(&port_auto(entry, is_peer, perms & BIND != 0));
            } else {
                s.push_str("...");
            }
        }
        let mut out = Vec::new();
        for s in streams.drain(..) {
            if entry.is_ip {
                out.push(format!("{s}{}", ip_cond(&entry.ip)));
            } else if entry.is_none {
                out.push(format!("{s}{}", hex(0)));
            } else {
                out.push(format!("{s}{}", hex(0)));
                out.push(format!("{s}{}....", hex(1)));
                out.push(format!("{s}{}{}", hex(2), ".".repeat(16)));
            }
        }
        *streams = out;
        let label = entry.label_match.is_some();
        let mut cond_perms = map_perms(perms);
        if (!is_cmd && (label || is_peer)) || is_iface {
            cond_perms = COMPAT_CONT_MATCH;
        }
        let audit = self.audit(perms);
        for s in streams.iter_mut() {
            s.push_str("\\x00");
            self.rule(set, s, cond_perms, audit)?;
            if is_iface {
                if perms & SEND != 0 {
                    s.push_str("(\\x00|");
                }
                s.push_str(&default_cond(&entry.iface, "iface")?);
                s.push_str("\\x00");
                if perms & SEND != 0 {
                    s.push(')');
                }
                let mut ifperms = if label || is_peer {
                    cond_perms
                } else {
                    map_perms(perms)
                };
                if perms & SEND != 0 {
                    ifperms |= SET_LABEL;
                }
                self.rule(set, s, ifperms, audit)?;
            }
            if label || is_peer {
                let lperms = if is_peer {
                    cond_perms
                } else {
                    map_perms(perms)
                };
                s.push_str(&default_cond(&entry.label_match, "label")?);
                if is_iface && !label {
                    self.rule(set, s, map_perms(perms), audit)?;
                }
                s.push_str("\\x00");
                self.rule(set, s, lperms, audit)?;
            }
        }
        Ok(())
    }

    /// One family's rules; `perm` is the family with its socket type and
    /// protocol masks.
    fn net_rule(
        &self,
        set: &mut RuleSet,
        s: &Support,
        class: u32,
        perm: (u32, u32, u32),
        skb: bool,
    ) -> Result<(), String> {
        let (family, types, protocol) = perm;
        let perms = self.head.perms;
        let is_iface = skb && s.ifacev9_skb;
        let family = family & 0xffff;
        let mut buffer = format!(
            "{}{}{}",
            hex(class),
            hex((family & 0xff00) >> 8),
            hex(family & 0xff)
        );
        if types > 0xffff || types == ALL_TYPES {
            buffer.push_str("..");
        } else {
            let single = types != 0 && types & (types - 1) == 0;
            if !single {
                buffer.push('(');
            }
            let mut first = true;
            for t in 0..16u32 {
                if types & (1 << t) != 0 {
                    if !first {
                        buffer.push('|');
                    }
                    first = false;
                    buffer.push_str(&hex((t & 0xff00) >> 8));
                    buffer.push_str(&hex(t & 0xff));
                }
            }
            if !single {
                buffer.push(')');
            }
        }
        if !skb && (!(s.inetv8 || s.inetv9) || (family != AF_INET && family != AF_INET6)) {
            return self.rule(set, &buffer, map_perms(perms), self.audit(perms));
        }
        self.rule(set, &buffer, COMPAT_CONT_MATCH, 0)?;
        if !skb && perms & CREATE != 0 {
            self.rule(
                set,
                &buffer,
                map_perms(perms & CREATE) | COMPAT_CONT_MATCH,
                self.audit(perms & CREATE),
            )?;
        }
        if protocol > 0xffff {
            buffer.push_str("..");
        } else {
            buffer.push_str(&hex((protocol & 0xff00) >> 8));
            buffer.push_str(&hex(protocol & 0xff));
        }
        if perms & PEER != 0 {
            let mut streams = vec![buffer.clone()];
            self.ip_conds(set, &mut streams, &self.peer, true, false, is_iface)?;
            for st in streams.iter_mut() {
                st.push_str(&hex(CMD_ADDR));
            }
            self.ip_conds(set, &mut streams, &self.local, false, true, is_iface)?;
        }
        if skb {
            return Ok(());
        }
        let mut streams = vec![buffer];
        self.ip_conds(set, &mut streams, &self.local, false, false, false)?;
        if perms & LISTEN != 0 {
            for st in &streams {
                let re = format!("{st}{}..", hex(CMD_LISTEN));
                self.rule(set, &re, map_perms(perms), self.audit(perms))?;
            }
        }
        if perms & OPT != 0 {
            for st in &streams {
                let re = format!("{st}{}....", hex(CMD_OPT));
                self.rule(set, &re, map_perms(perms), self.audit(perms))?;
            }
        }
        Ok(())
    }

    pub fn gen(&self, set: &mut RuleSet, s: &Support) -> Result<(), String> {
        if !(s.networkv8 || s.networkv9) {
            return Ok(());
        }
        let class = if s.networkv9 {
            CLASS_NETV9
        } else {
            CLASS_NETV8
        };
        for (&family, &(types, protocol)) in &self.perms_map {
            self.net_rule(set, s, class, (family, types, protocol), false)?;
            if s.networkv9_skb {
                self.net_rule(set, s, CLASS_NETV9_SKB, (family, types, protocol), true)?;
            }
        }
        Ok(())
    }
}
