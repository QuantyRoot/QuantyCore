//! Our policy in a real kernel: profiles compiled here are loaded through
//! securityfs, a copy of this test binary is started under each through
//! the exec attribute, and what it may and may not do is checked against
//! what the kernel answers: files, the network, capabilities and signals.
//!
//! Needs root and a kernel with AppArmor enabled. Runs when
//! `QUANTY_APPARMOR_KERNEL` is set, as in the CI job on an Ubuntu runner;
//! with `QUANTY_VECTORS_REQUIRED` set and no kernel, it fails.

use std::io::Read;
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use quantycore::apparmor::binary::{serialize, Unit};
use quantycore::apparmor::kernel::{fqname, ExecTransition, Securityfs};
use quantycore::apparmor::runtime_default::RuntimeDefault;
use quantycore::apparmor::{compile, Features, MemResolver, Options};

const OP: &str = "QUANTY_AA_OP";
const EACCES: i32 = 13;
const EPERM: i32 = 1;
const OTHER: i32 = 250;
const WRONG_LABEL: i32 = 251;
const SPAWN_FAILED: i32 = 252;

/// Per feature set: 26 operations in `checks` (one fewer against the
/// default abi), a refused second load, eight profiles listed and none
/// left after removing.
const MIN_CHECKS: usize = 2 * 36 - 1;

/// What the confined copy does: one operation, answered by the exit
/// code, which is the errno when it fails.
#[test]
fn helper() {
    let Ok(op) = std::env::var(OP) else {
        return;
    };
    let code = match run_op(&op) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("helper {op}: {e}");
            e.raw_os_error()
                .filter(|&c| c > 0 && c < 200)
                .unwrap_or(OTHER)
        }
    };
    std::process::exit(code);
}

fn run_op(op: &str) -> std::io::Result<()> {
    let (verb, arg) = op.split_once(':').unwrap_or((op, ""));
    match verb {
        "label" => {
            let mut s = String::new();
            std::fs::File::open("/proc/self/attr/current")?.read_to_string(&mut s)?;
            if s.trim_end_matches(['\n', '\0']) != format!("{arg} (enforce)") {
                std::process::exit(WRONG_LABEL);
            }
            Ok(())
        }
        "read" => std::fs::read(arg).map(|_| ()),
        "write" => std::fs::write(arg, b"x"),
        "connect" => {
            TcpStream::connect((Ipv4Addr::LOCALHOST, arg.parse::<u16>().unwrap())).map(|_| ())
        }
        "chown" => std::os::unix::fs::chown(arg, Some(1), Some(1)),
        "true" => {
            let st = Command::new("/bin/true").status()?;
            if !st.success() {
                std::process::exit(SPAWN_FAILED);
            }
            Ok(())
        }
        "spawn" => {
            let st = helper_command("sleep").status()?;
            if !st.success() {
                std::process::exit(SPAWN_FAILED);
            }
            Ok(())
        }
        "signal" => {
            let Ok(mut child) = helper_command("sleep").spawn() else {
                std::process::exit(SPAWN_FAILED);
            };
            let r = child.kill();
            child.wait()?;
            r
        }
        "sleep" => {
            std::thread::sleep(std::time::Duration::from_millis(500));
            Ok(())
        }
        _ => std::process::exit(OTHER),
    }
}

fn helper_command(op: &str) -> Command {
    let mut c = Command::new(std::env::current_exe().unwrap());
    c.args(["--exact", "helper", "--test-threads", "1", "-q"])
        .env(OP, op)
        .stdin(Stdio::null())
        .stdout(Stdio::null());
    c
}

/// Starts the helper under `profile` and returns its exit code. The exec
/// attribute belongs to the thread that writes it and is inherited by
/// the child that thread starts, so each run gets a thread of its own.
fn confined(profile: &str, op: &str) -> i32 {
    let profile = profile.to_string();
    let op = op.to_string();
    std::thread::spawn(move || {
        let t = ExecTransition::prepare(profile.as_bytes()).unwrap();
        t.apply(Path::new("/proc")).unwrap();
        let st = helper_command(&op).status().unwrap();
        st.code().unwrap_or(-1)
    })
    .join()
    .unwrap()
}

fn compile_units(text: &str, kernel: &Features, policy: Option<Features>) -> Vec<Unit> {
    let opts = Options {
        kernel_features: kernel.clone(),
        policy_features: policy,
        ..Options::default()
    };
    let mut r = MemResolver::default();
    let p = compile(&mut r, "kernel-test", text.as_bytes().to_vec(), &opts)
        .unwrap_or_else(|e| panic!("{e}"));
    serialize(&p, &p.support).unwrap()
}

struct Run {
    checks: usize,
    failures: Vec<String>,
}

impl Run {
    fn expect(&mut self, profile: &str, op: &str, want: i32) {
        let got = confined(profile, op);
        self.checks += 1;
        if got != want {
            self.failures
                .push(format!("{profile} {op}: exit {got}, expected {want}"));
        }
    }
}

fn profiles_text(tag: &str, dir: &Path) -> String {
    let d = dir.display();
    // The test binary sits under the runner's home directory, which root
    // walks into only with these two capabilities.
    let base = "/** rwlkmix,\n  capability dac_override dac_read_search,";
    format!(
        "profile quanty_aa_files_{tag} {{\n  {base}\n  deny {d}/secret r,\n  deny {d}/ro w,\n}}\n\
         profile quanty_aa_net_allow_{tag} {{\n  {base}\n  network inet stream,\n}}\n\
         profile quanty_aa_net_deny_{tag} {{\n  {base}\n}}\n\
         profile quanty_aa_cap_allow_{tag} {{\n  {base}\n  capability chown,\n}}\n\
         profile quanty_aa_cap_deny_{tag} {{\n  {base}\n}}\n\
         profile quanty_aa_sig_allow_{tag} {{\n  {base}\n  \
         signal (send, receive) peer=quanty_aa_sig_allow_{tag},\n}}\n\
         profile quanty_aa_sig_deny_{tag} {{\n  {base}\n}}\n"
    )
}

fn checks(run: &mut Run, tag: &str, dir: &Path, port: u16) {
    let p = |n: &str| format!("quanty_aa_{n}_{tag}");
    let f = |n: &str| dir.join(n).display().to_string();
    for n in [
        "files",
        "net_allow",
        "net_deny",
        "cap_allow",
        "cap_deny",
        "sig_allow",
        "sig_deny",
    ] {
        run.expect(&p(n), &format!("label:{}", p(n)), 0);
    }
    run.expect(&p("files"), &format!("read:{}", f("open")), 0);
    run.expect(&p("files"), &format!("read:{}", f("secret")), EACCES);
    run.expect(&p("files"), &format!("write:{}", f("open")), 0);
    run.expect(&p("files"), &format!("write:{}", f("ro")), EACCES);
    run.expect(&p("files"), &format!("read:{}", f("ro")), 0);
    run.expect(&p("net_allow"), &format!("connect:{port}"), 0);
    // Upstream's default abi puts network rules into the old table,
    // which mainline kernels do not read; there is nothing to refuse.
    if tag != "d" {
        run.expect(&p("net_deny"), &format!("connect:{port}"), EACCES);
    }
    run.expect(&p("net_deny"), &format!("read:{}", f("open")), 0);
    run.expect(&p("cap_allow"), &format!("chown:{}", f("own")), 0);
    // A capability AppArmor refuses fails the way a missing one does.
    run.expect(&p("cap_deny"), &format!("chown:{}", f("own")), EPERM);
    run.expect(&p("sig_allow"), "true", 0);
    run.expect(&p("sig_allow"), "spawn", 0);
    run.expect(&p("sig_allow"), "signal", 0);
    run.expect(&p("sig_deny"), "signal", EACCES);
    run.expect(&p("sig_deny"), &format!("read:{}", f("open")), 0);
    run.expect(&p("cap_deny"), &format!("read:{}", f("secret")), 0);
    run.expect(&p("rd"), &format!("label:{}", p("rd")), 0);
    run.expect(&p("rd"), &format!("read:{}", f("open")), 0);
    run.expect(&p("rd"), "write:/proc/sys/vm/drop_caches", EACCES);
}

fn scratch() -> PathBuf {
    let d = std::env::temp_dir().join(format!("quanty-aa-kernel-{}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    for n in ["open", "secret", "ro", "own"] {
        std::fs::write(d.join(n), b"data").unwrap();
    }
    d
}

#[test]
fn kernel() {
    if std::env::var_os("QUANTY_APPARMOR_KERNEL").is_none() {
        if std::env::var_os("QUANTY_VECTORS_REQUIRED").is_some() {
            panic!("QUANTY_APPARMOR_KERNEL not set but QUANTY_VECTORS_REQUIRED is");
        }
        eprintln!("QUANTY_APPARMOR_KERNEL not set, skipping");
        return;
    }
    let fs = Securityfs::system();
    let kernel = fs.features().expect("AppArmor's securityfs is readable");
    let dir = scratch();
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for s in listener.incoming() {
            drop(s);
        }
    });
    let mut run = Run {
        checks: 0,
        failures: Vec::new(),
    };
    // Once against upstream's default abi, which puts the network rules
    // in the old table, and once against everything this kernel offers.
    for (tag, policy) in [("d", None), ("k", Some(kernel.clone()))] {
        let rd = RuntimeDefault::bare(&format!("quanty_aa_rd_{tag}")).render();
        let mut units = compile_units(&profiles_text(tag, &dir), &kernel, policy.clone());
        units.extend(compile_units(&rd, &kernel, policy));
        assert_eq!(units.len(), 8);
        let first = &units[..1];
        let _ = fs.remove(&fqname(&first[0]));
        fs.load(first).unwrap();
        let again = fs.load(first).unwrap_err();
        run.checks += 1;
        if again.raw_os_error() != Some(17) {
            run.failures
                .push(format!("second load of one name: {again}, expected EEXIST"));
        }
        fs.replace(&units).unwrap();
        let loaded = fs.profiles().unwrap();
        for u in &units {
            run.checks += 1;
            let hit = loaded
                .iter()
                .any(|l| l.name == u.name && l.mode == b"enforce");
            if !hit {
                run.failures.push(format!(
                    "{} not listed in enforce mode",
                    String::from_utf8_lossy(&u.name)
                ));
            }
        }
        checks(&mut run, tag, &dir, port);
        for u in &units {
            fs.remove(&fqname(u)).unwrap();
        }
        let loaded = fs.profiles().unwrap();
        run.checks += 1;
        if units
            .iter()
            .any(|u| loaded.iter().any(|l| l.name == u.name))
        {
            run.failures
                .push("a removed profile is still listed".into());
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
    eprintln!(
        "{} kernel checks, {} failed",
        run.checks,
        run.failures.len()
    );
    for f in &run.failures {
        eprintln!("  {f}");
    }
    assert!(run.failures.is_empty());
    assert!(run.checks >= MIN_CHECKS, "only {} checks ran", run.checks);
}
