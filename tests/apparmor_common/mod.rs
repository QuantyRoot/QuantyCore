//! What the AppArmor tests share: reading upstream's test cases, and
//! reading the binary policy `apparmor_parser` writes, far enough to run
//! its automata the way the kernel runs them.
//!
//! The policy is a stream of typed values (security/apparmor/policy_unpack.c
//! in Linux reads it); an automaton inside it is a set of flex style
//! tables, matched by the kernel's match.c.

#![allow(dead_code)]

use std::path::{Path, PathBuf};

pub struct Case {
    pub expect_pass: bool,
    pub todo: bool,
    pub disabled: bool,
    pub body: Vec<u8>,
}

pub fn read_case(path: &Path) -> Case {
    let text = std::fs::read(path).unwrap();
    let mut expect_pass = true;
    let mut todo = false;
    let mut disabled = false;
    let mut body = Vec::new();
    for line in text.split_inclusive(|&b| b == b'\n') {
        if line.len() >= 13 && line[..13].eq_ignore_ascii_case(b"#=DESCRIPTION") {
            continue;
        }
        if let Some(rest) = line.strip_prefix(b"#=EXRESULT") {
            let word: Vec<u8> = rest
                .iter()
                .copied()
                .skip_while(|b| b.is_ascii_whitespace())
                .take_while(|b| b.is_ascii_alphanumeric() || *b == b'_')
                .collect();
            expect_pass = match &word[..] {
                b"PASS" => true,
                b"FAIL" => false,
                other => panic!("{}: unknown result {:?}", path.display(), other),
            };
        } else if line.starts_with(b"#=TODO") {
            todo = true;
        } else if line.starts_with(b"#=DISABLED") {
            disabled = true;
        } else if !disabled {
            body.extend_from_slice(line);
        }
    }
    Case {
        expect_pass,
        todo,
        disabled,
        body,
    }
}

pub fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
    for e in std::fs::read_dir(dir).unwrap() {
        let p = e.unwrap().path();
        if p.is_dir() {
            walk(&p, out);
        } else if p.extension().is_some_and(|x| x == "sd") {
            out.push(p);
        }
    }
}

/// One value of the policy stream.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Tlv {
    Name(Vec<u8>),
    U8(u8),
    U16(u16),
    U32(u32),
    U64(u64),
    Str(Vec<u8>),
    Blob(Vec<u8>),
    Struct,
    StructEnd,
    List,
    ListEnd,
    Array(u16),
    ArrayEnd,
}

pub fn tlv(buf: &[u8]) -> Result<Vec<Tlv>, String> {
    let mut out = Vec::new();
    let mut i = 0;
    let take = |i: &mut usize, n: usize| -> Result<&[u8], String> {
        let s = buf
            .get(*i..*i + n)
            .ok_or_else(|| format!("truncated at {}", *i))?;
        *i += n;
        Ok(s)
    };
    while i < buf.len() {
        let code = buf[i];
        i += 1;
        let v = match code {
            0 => Tlv::U8(take(&mut i, 1)?[0]),
            1 => Tlv::U16(u16::from_le_bytes(take(&mut i, 2)?.try_into().unwrap())),
            2 => Tlv::U32(u32::from_le_bytes(take(&mut i, 4)?.try_into().unwrap())),
            3 => Tlv::U64(u64::from_le_bytes(take(&mut i, 8)?.try_into().unwrap())),
            4 | 5 => {
                let n = u16::from_le_bytes(take(&mut i, 2)?.try_into().unwrap()) as usize;
                let s = take(&mut i, n)?.to_vec();
                if code == 4 {
                    Tlv::Name(s)
                } else {
                    Tlv::Str(s)
                }
            }
            6 => {
                let n = u32::from_le_bytes(take(&mut i, 4)?.try_into().unwrap()) as usize;
                Tlv::Blob(take(&mut i, n)?.to_vec())
            }
            7 => Tlv::Struct,
            8 => Tlv::StructEnd,
            9 => Tlv::List,
            10 => Tlv::ListEnd,
            11 => Tlv::Array(u16::from_le_bytes(take(&mut i, 2)?.try_into().unwrap())),
            12 => Tlv::ArrayEnd,
            c => return Err(format!("unknown code {c} at {}", i - 1)),
        };
        out.push(v);
    }
    Ok(out)
}

/// An automaton as the kernel holds it.
#[derive(Debug, Default)]
pub struct Tables {
    pub flags: u16,
    pub accept: Vec<u32>,
    pub accept2: Vec<u32>,
    pub ec: Vec<u8>,
    pub base: Vec<u32>,
    pub def: Vec<u32>,
    pub next: Vec<u32>,
    pub check: Vec<u32>,
}

const DIFF_ENCODE: u32 = 0x8000_0000;
const OOB_TRANSITION: u32 = 0x2000_0000;

impl Tables {
    /// Reads an `aadfa` blob, whose first bytes may be alignment padding.
    pub fn read(blob: &[u8]) -> Result<Tables, String> {
        let start = blob
            .iter()
            .position(|&b| b != 0)
            .filter(|&p| p < 8)
            .ok_or("no table header")?;
        let b = &blob[start..];
        let be32 = |o: usize| -> Result<u32, String> {
            b.get(o..o + 4)
                .map(|s| u32::from_be_bytes(s.try_into().unwrap()))
                .ok_or_else(|| "truncated table".to_string())
        };
        let be16 = |o: usize| -> Result<u16, String> {
            b.get(o..o + 2)
                .map(|s| u16::from_be_bytes(s.try_into().unwrap()))
                .ok_or_else(|| "truncated table".to_string())
        };
        if be32(0)? != 0x1B5E_783D {
            return Err("bad magic".into());
        }
        let hsize = be32(4)? as usize;
        let ssize = be32(8)? as usize;
        let mut t = Tables {
            flags: be16(12)?,
            ..Tables::default()
        };
        let mut o = hsize;
        while o < ssize.min(b.len()) {
            let id = be16(o)?;
            let width = be16(o + 2)? as usize;
            let len = be32(o + 8)? as usize;
            let data = b
                .get(o + 12..o + 12 + len * width)
                .ok_or("truncated table data")?;
            let vals: Vec<u32> = data
                .chunks(width)
                .map(|c| c.iter().fold(0u32, |a, &x| (a << 8) | x as u32))
                .collect();
            match id {
                1 => t.accept = vals,
                2 => t.base = vals,
                3 => t.check = vals,
                4 => t.def = vals,
                5 => t.ec = vals.iter().map(|&v| v as u8).collect(),
                7 => t.accept2 = vals,
                8 => t.next = vals,
                other => return Err(format!("unknown table {other}")),
            }
            o += (12 + len * width).div_ceil(8) * 8;
        }
        if t.base.len() != t.def.len()
            || t.next.len() != t.check.len()
            || t.accept.len() != t.base.len()
        {
            return Err("table lengths disagree".into());
        }
        Ok(t)
    }

    pub fn states(&self) -> usize {
        self.base.len()
    }

    /// The kernel's match_char, with the state chain bounded.
    fn step(&self, mut state: u32, pos_of: impl Fn(u32) -> Option<usize>) -> Result<u32, String> {
        for _ in 0..=self.states() {
            let b = *self.base.get(state as usize).ok_or("state out of range")?;
            let pos = pos_of(b);
            let hit = pos.is_some_and(|p| self.check.get(p) == Some(&state));
            if hit {
                let p = pos.unwrap();
                return Ok(self.next[p]);
            }
            state = *self.def.get(state as usize).ok_or("default out of range")?;
            if b & DIFF_ENCODE == 0 {
                return Ok(state);
            }
        }
        Err("default chain loops".into())
    }

    pub fn next(&self, state: u32, c: u8) -> Result<u32, String> {
        let c = if self.ec.is_empty() {
            c as usize
        } else {
            self.ec[c as usize] as usize
        };
        self.step(state, |b| Some((b & 0x00ff_ffff) as usize + c))
    }

    pub fn next_oob(&self, state: u32) -> Result<u32, String> {
        let b = *self.base.get(state as usize).ok_or("state out of range")?;
        if b & OOB_TRANSITION == 0 {
            return Ok(0);
        }
        self.step(state, |b| ((b & 0x00ff_ffff) as usize).checked_sub(1))
    }
}

/// One profile of a policy, as far as the comparison reads it.
#[derive(Debug, Default)]
pub struct BinProfile {
    pub name: Vec<u8>,
    pub namespace: Option<Vec<u8>>,
    pub xmatch: Option<(Tables, u32)>,
    pub file: Option<Tables>,
    pub policydb: Option<Tables>,
    pub xtable: Vec<Vec<u8>>,
}

/// Splits a policy stream into its profiles.
pub fn profiles(buf: &[u8]) -> Result<Vec<BinProfile>, String> {
    let v = tlv(buf)?;
    let mut out = Vec::new();
    let mut i = 0;
    while i < v.len() {
        if v[i] != Tlv::Name(b"version\0".to_vec()) {
            return Err(format!("expected version at value {i}"));
        }
        i += 2;
        let mut p = BinProfile::default();
        if v.get(i) == Some(&Tlv::Name(b"namespace\0".to_vec())) {
            if let Some(Tlv::Str(s)) = v.get(i + 1) {
                p.namespace = Some(trim_nul(s));
            }
            i += 2;
        }
        if v.get(i) != Some(&Tlv::Name(b"profile\0".to_vec())) || v.get(i + 1) != Some(&Tlv::Struct)
        {
            return Err("expected profile struct".into());
        }
        i += 2;
        match v.get(i) {
            Some(Tlv::Str(s)) => p.name = trim_nul(s),
            _ => return Err("profile without name".into()),
        }
        i += 1;
        let mut depth = 1;
        let mut seen_flags = false;
        let mut in_policydb = false;
        let mut in_xtable = false;
        let mut last_name: Option<Vec<u8>> = None;
        while depth > 0 {
            let t = v.get(i).ok_or("unterminated profile")?;
            i += 1;
            match t {
                Tlv::Name(n) => {
                    last_name = Some(n.clone());
                    continue;
                }
                Tlv::Struct => {
                    depth += 1;
                    let n = last_name.take().unwrap_or_default();
                    if depth == 2 && n == b"flags\0" {
                        seen_flags = true;
                    }
                    in_policydb = depth == 2 && n == b"policydb\0" || in_policydb && depth > 2;
                    in_xtable = n == b"xtable\0";
                }
                Tlv::StructEnd => {
                    depth -= 1;
                    if depth == 1 {
                        in_policydb = false;
                        in_xtable = false;
                    }
                }
                Tlv::Blob(b) if last_name.as_deref() == Some(b"aadfa\0") => {
                    let tables = Tables::read(b)?;
                    if in_policydb {
                        p.policydb = Some(tables);
                    } else if !seen_flags {
                        let len = match v.get(i) {
                            Some(Tlv::U32(l)) => *l,
                            _ => return Err("xmatch without length".into()),
                        };
                        i += 1;
                        p.xmatch = Some((tables, len));
                    } else {
                        p.file = Some(tables);
                    }
                }
                Tlv::Str(s) if in_xtable && depth == 2 => p.xtable.push(s.clone()),
                _ => {}
            }
            last_name = None;
        }
        out.push(p);
    }
    Ok(out)
}

fn trim_nul(s: &[u8]) -> Vec<u8> {
    s.strip_suffix(b"\0").unwrap_or(s).to_vec()
}
