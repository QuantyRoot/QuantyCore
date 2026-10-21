//! A seed driven fuzzer for the AppArmor compiler: profile text from
//! seeds, mutated byte by byte and token by token, compiled against
//! several kernels' features, and the kernel's feature text itself.
//!
//! The properties: nothing panics, every case ends within the limits it
//! was given, and whatever is accepted is written as a policy the
//! kernel's unpacker would take, with automata that pass the kernel's own
//! checks (verify_dfa, verify_perms). Refusals are expected.
//!
//! Seeds are the profiles below and, when `QUANTY_APPARMOR_TST` points at
//! upstream's `parser/tst`, every simple_tests case and upstream's abi
//! files. Every case is derived from `QUANTY_FUZZ_SEED` (default 1) and
//! its iteration number, so a failure prints both and
//! `QUANTY_FUZZ_SEED=s QUANTY_FUZZ_FROM=i QUANTY_FUZZ_ITERS=1` replays it.

mod apparmor_common;

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use apparmor_common::profiles;
use quantycore::apparmor::binary::serialize;
use quantycore::apparmor::compile::dfa::Limits;
use quantycore::apparmor::features::DEFAULT_ABI;
use quantycore::apparmor::kernel::parse_profiles;
use quantycore::apparmor::runtime_default::RuntimeDefault;
use quantycore::apparmor::{compile, Features, MemResolver, Options};

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e3779b97f4a7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
        z ^ (z >> 31)
    }
    fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            0
        } else {
            (self.next() % n as u64) as usize
        }
    }
}

fn env(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

/// Words of the language, spliced in where plain bytes would rarely
/// reach the parser's later stages.
const TOKENS: &[&str] = &[
    "{",
    "}",
    ",",
    "(",
    ")",
    "=",
    "+=",
    "->",
    "<",
    ">",
    "\"",
    "\n",
    " ",
    "#",
    "\\",
    "@{",
    "@{x}",
    "${",
    "$b",
    "*",
    "**",
    "?",
    "[",
    "]",
    "[^",
    "{a,b}",
    "{,",
    "^",
    "//",
    "/",
    ":",
    "deny",
    "allow",
    "audit",
    "owner",
    "other",
    "priority=",
    "priority=-1001",
    "quiet",
    "complain",
    "kill",
    "prompt",
    "if",
    "else",
    "defined",
    "not",
    "and",
    "or",
    "profile",
    "hat",
    "^h",
    "flags=(",
    "xattrs=(",
    "abi",
    "include",
    "#include",
    "include if exists",
    "<tunables/global>",
    "<abstractions/loop>",
    "alias",
    "capability",
    "network",
    "unix",
    "dbus",
    "signal",
    "ptrace",
    "mount",
    "umount",
    "remount",
    "pivot_root",
    "rlimit",
    "set",
    "change_profile",
    "userns",
    "io_uring",
    "mqueue",
    "all",
    "link",
    "subset",
    "file",
    "peer=",
    "label=",
    "addr=",
    "type=",
    "set=(",
    "fstype=",
    "options=(",
    "inet",
    "inet6",
    "stream",
    "dgram",
    "ip=",
    "port=",
    "r",
    "w",
    "rw",
    "a",
    "l",
    "k",
    "m",
    "ix",
    "px",
    "Px",
    "cx",
    "Cx",
    "ux",
    "Ux",
    "pix",
    "Cix",
    "pux",
    "CUx",
    "unsafe",
    "safe",
    "bus=",
    "path=",
    "member=",
    "name=",
    "send",
    "receive",
    "bind",
    "listen",
    "connect",
    "read",
    "trace",
    "readby",
    "tracedby",
    "create",
    "sqpoll",
    "override_creds",
    "posix",
    "sysv",
    "rtmin+",
    "rtmin+33",
    "0",
    "65535",
    "4294967296",
    "-1",
    "/{**,}",
    "@{PROC}",
    "@{HOME}",
    "\u{0}",
    "\u{ff}",
];

fn mutate_bytes(rng: &mut Rng, v: &mut Vec<u8>, other: &[u8]) {
    let len = v.len();
    match rng.below(6) {
        0 if len > 0 => {
            let i = rng.below(len);
            v[i] ^= 1 << rng.below(8);
        }
        1 if len > 0 => {
            let a = rng.below(len);
            let b = (a + 1 + rng.below(24)).min(len);
            v.drain(a..b);
        }
        2 if len > 0 => {
            let a = rng.below(len);
            let b = (a + 1 + rng.below(48)).min(len);
            let chunk = v[a..b].to_vec();
            let at = rng.below(len);
            v.splice(at..at, chunk);
        }
        3 if !other.is_empty() => {
            let a = rng.below(other.len());
            let b = (a + 1 + rng.below(96)).min(other.len());
            let at = rng.below(len + 1);
            v.splice(at..at, other[a..b].iter().copied());
        }
        4 if len > 0 => v.truncate(rng.below(len)),
        _ => {
            let at = rng.below(len + 1);
            let n = rng.below(6);
            let bytes: Vec<u8> = (0..n).map(|_| rng.next() as u8).collect();
            v.splice(at..at, bytes);
        }
    }
}

/// Replaces a word, or inserts one, at a word boundary.
fn mutate_tokens(rng: &mut Rng, v: &mut Vec<u8>) {
    let t = TOKENS[rng.below(TOKENS.len())].as_bytes();
    let bounds: Vec<usize> = (0..=v.len())
        .filter(|&i| i == 0 || i == v.len() || !v[i - 1].is_ascii_alphanumeric())
        .collect();
    let at = bounds[rng.below(bounds.len())];
    if rng.below(2) == 0 {
        let end = v[at..]
            .iter()
            .position(|c| !c.is_ascii_alphanumeric())
            .map_or(v.len(), |p| at + p.max(1).min(v.len() - at));
        v.splice(at..end, t.iter().copied());
    } else {
        v.splice(at..at, t.iter().copied());
    }
}

fn mutate(rng: &mut Rng, input: &[u8], other: &[u8]) -> Vec<u8> {
    let mut v = input.to_vec();
    for _ in 0..1 + rng.below(6) {
        if rng.below(3) == 0 {
            mutate_bytes(rng, &mut v, other);
        } else {
            mutate_tokens(rng, &mut v);
        }
    }
    v
}

const SEEDS: &[&str] = &[
    r#"
abi <abi/3.0>,
include <tunables/global>
@{X} = /a /b{c,d}
@{X} += /e
$b = true
alias /usr/ -> /opt/,
/usr/bin/app flags=(complain, attach_disconnected) xattrs=(user.a="b*") {
  include <abstractions/base>
  audit deny @{X}/** w,
  owner @{HOME}/** rwlk,
  /bin/** Pix -> other,
  /sbin/* cx -> child,
  link subset /l -> /t,
  capability chown dac_override,
  network inet stream,
  deny network inet6 dgram,
  unix (send, receive) type=stream peer=(label=x, addr="@a*"),
  dbus send bus=session path=/a member=m peer=(name=n),
  signal (send) set=(hup, rtmin+3) peer=p,
  ptrace (read, trace) peer=q,
  mount fstype=ext4 options=(ro, nodev) /dev/sd* -> /mnt/,
  umount /mnt/**,
  pivot_root oldroot=/o/ /n/ -> q,
  rlimit nofile <= 1024,
  change_profile -> other,
  userns create,
  io_uring sqpoll label=l,
  mqueue (read, write) type=posix /q,
  priority=5 /p r,
  if $b { /t r, } else { /f r, }
  if defined @{X} and not $b { /g w, }
  ^hat { /h r, }
  profile child { /c ix, }
}
"#,
    "profile a /a { all, }\nprofile b { deny all, }\n",
    "/x { /** rwlkmix, deny /x/s r, network, signal, ptrace, mount, file, }\n",
    "#include <abstractions/loop>\n/y { }\n",
    ":ns:/z { owner /z/{,**} r, /z/a/[^b]*? w, }\n",
];

fn resolver() -> MemResolver {
    let f = |p: &str, t: &str| (p.as_bytes().to_vec(), t.as_bytes().to_vec());
    MemResolver {
        search: vec![b"/etc/apparmor.d".to_vec()],
        files: vec![
            f(
                "/etc/apparmor.d/tunables/global",
                "@{PROC}=/proc/\n@{HOME}=/home/*/ /root/\n",
            ),
            f(
                "/etc/apparmor.d/abstractions/base",
                "/etc/ld.so.cache r,\n/{usr/,}lib{,32,64}/** mr,\nsignal (receive) peer=unconfined,\n",
            ),
            f(
                "/etc/apparmor.d/abstractions/loop",
                "include <abstractions/loop>\n",
            ),
            f("/etc/apparmor.d/abi/3.0", DEFAULT_ABI),
        ],
    }
}

struct Seeds {
    profiles: Vec<Vec<u8>>,
    features: Vec<Features>,
}

fn seeds() -> Seeds {
    let mut s = Seeds {
        profiles: SEEDS.iter().map(|s| s.as_bytes().to_vec()).collect(),
        features: vec![Features::from_text(DEFAULT_ABI.as_bytes()).unwrap()],
    };
    s.profiles
        .push(RuntimeDefault::bare("rd").render().into_bytes());
    let tst = match std::env::var_os("QUANTY_APPARMOR_TST") {
        Some(t) => PathBuf::from(t),
        None => {
            if std::env::var_os("QUANTY_VECTORS_REQUIRED").is_some() {
                panic!("QUANTY_APPARMOR_TST not set but QUANTY_VECTORS_REQUIRED is");
            }
            return s;
        }
    };
    let mut files = Vec::new();
    apparmor_common::walk(&tst.join("simple_tests"), &mut files);
    files.sort();
    for f in files {
        if f.extension().is_some_and(|e| e == "sd") {
            s.profiles.push(std::fs::read(&f).unwrap());
        }
    }
    let abi = tst.join("../../profiles/apparmor.d/abi");
    for p in [
        tst.join("features_files/features.all"),
        abi.join("4.0"),
        abi.join("5.0"),
        abi.join("5.0-interface"),
    ] {
        let t = std::fs::read(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()));
        s.features.push(Features::from_text(&t).unwrap());
    }
    assert!(
        s.profiles.len() > 2000,
        "simple_tests not found under {}",
        tst.display()
    );
    s
}

/// Small enough that an exploding case ends quickly, large enough for
/// every seed.
const LIMITS: Limits = Limits {
    max_states: 1 << 14,
    max_positions: 1 << 22,
    max_tree_steps: 1 << 24,
};

struct Stats {
    accepted: u64,
    refused: u64,
    automata: u64,
    slowest: Duration,
}

/// Compiles one case; whatever is accepted must serialize and pass the
/// kernel's checks.
fn check_case(text: Vec<u8>, kernel: &Features, policy: Option<&Features>, st: &mut Stats) {
    let opts = Options {
        kernel_features: kernel.clone(),
        policy_features: policy.cloned(),
        limits: LIMITS,
    };
    let start = Instant::now();
    let r = compile(&mut resolver(), "fuzz", text, &opts);
    let p = match r {
        Ok(p) => p,
        Err(_) => {
            st.refused += 1;
            st.slowest = st.slowest.max(start.elapsed());
            return;
        }
    };
    st.accepted += 1;
    let units = match serialize(&p, &p.support) {
        Ok(u) => u,
        // The 16 bit state limit refuses at writing time.
        Err(_) => return,
    };
    st.slowest = st.slowest.max(start.elapsed());
    for u in &units {
        let bin = profiles(&u.data).unwrap_or_else(|e| panic!("written policy unreadable: {e}"));
        for b in &bin {
            let tables = [
                b.xmatch.as_ref().map(|x| &x.0),
                b.file.as_ref(),
                b.policydb.as_ref(),
            ];
            for t in tables.into_iter().flatten() {
                t.verify()
                    .unwrap_or_else(|e| panic!("kernel would refuse an automaton: {e}"));
                st.automata += 1;
            }
        }
    }
}

fn run(name: &str, cases: u64, mut target: impl FnMut(&mut Rng, &mut Stats)) {
    let seed = env("QUANTY_FUZZ_SEED", 1);
    let from = env("QUANTY_FUZZ_FROM", 0);
    let iters = env("QUANTY_FUZZ_ITERS", cases);
    let mut st = Stats {
        accepted: 0,
        refused: 0,
        automata: 0,
        slowest: Duration::ZERO,
    };
    for i in from..from + iters {
        let mut rng = Rng(seed ^ i.wrapping_mul(0xd1342543de82ef95) ^ name.len() as u64);
        if catch_unwind(AssertUnwindSafe(|| target(&mut rng, &mut st))).is_err() {
            panic!(
                "{name}: panic at QUANTY_FUZZ_SEED={seed} QUANTY_FUZZ_FROM={i} QUANTY_FUZZ_ITERS=1"
            );
        }
    }
    eprintln!(
        "{name}: {iters} cases, {} accepted, {} refused, {} automata verified, slowest {:?}",
        st.accepted, st.refused, st.automata, st.slowest
    );
    assert_eq!(st.accepted + st.refused, iters);
    if iters >= 1000 {
        assert!(
            st.accepted > 0 && st.refused > 0,
            "{name} never reached one side"
        );
    }
}

#[test]
fn fuzz_profile_text() {
    let s = seeds();
    run("profile_text", 3000, |rng, st| {
        let a = &s.profiles[rng.below(s.profiles.len())];
        let b = &s.profiles[rng.below(s.profiles.len())];
        // Some cases unchanged, so that acceptance and writing of the
        // seeds themselves are checked too.
        let text = if rng.below(8) == 0 {
            a.clone()
        } else {
            mutate(rng, a, b)
        };
        let k = &s.features[rng.below(s.features.len())];
        let pol = match rng.below(3) {
            0 => Some(&s.features[rng.below(s.features.len())]),
            _ => None,
        };
        check_case(text, k, pol, st);
    });
}

#[test]
fn fuzz_features_text() {
    let s = seeds();
    let texts: Vec<Vec<u8>> = s.features.iter().map(|f| f.text().to_vec()).collect();
    run("features_text", 1500, |rng, st| {
        let a = &texts[rng.below(texts.len())];
        let b = &texts[rng.below(texts.len())];
        let mut t = a.clone();
        for _ in 0..1 + rng.below(4) {
            mutate_bytes(rng, &mut t, b);
        }
        let Ok(k) = Features::from_text(&t) else {
            st.refused += 1;
            return;
        };
        let p = &s.profiles[rng.below(s.profiles.len().min(SEEDS.len() + 1))];
        let as_policy = rng.below(2) == 0;
        check_case(p.clone(), &k, as_policy.then_some(&k), st);
    });
}

#[test]
fn fuzz_profiles_list() {
    let mut seen = 0u64;
    run("profiles_list", 3000, |rng, st| {
        let mut t = b"a (enforce)\n:ns:b//c (complain)\nd e (kill)\n".to_vec();
        for _ in 0..1 + rng.below(4) {
            mutate_bytes(rng, &mut t, b" ()\n");
        }
        match parse_profiles(&t) {
            Ok(v) => {
                seen += v.len() as u64;
                st.accepted += 1;
            }
            Err(_) => st.refused += 1,
        }
    });
    assert!(seen > 0);
}
