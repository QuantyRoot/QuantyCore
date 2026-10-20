//! Names the profile language uses for kernel numbers: capabilities,
//! resource limits, signals and error codes, for x86_64 Linux, the one
//! architecture the consumers run on.

/// Capability name, number, and the capability older kernels check
/// instead (CAP_SYS_ADMIN for the ones split out of it), as upstream's
/// table has them.
pub(crate) const CAPABILITIES: &[(&[u8], u32, Option<u32>)] = &[
    (b"audit_control", 30, None),
    (b"audit_read", 37, None),
    (b"audit_write", 29, None),
    (b"block_suspend", 36, None),
    (b"bpf", 39, Some(21)),
    (b"checkpoint_restore", 40, Some(21)),
    (b"chown", 0, None),
    (b"dac_override", 1, None),
    (b"dac_read_search", 2, None),
    (b"fowner", 3, None),
    (b"fsetid", 4, None),
    (b"ipc_lock", 14, None),
    (b"ipc_owner", 15, None),
    (b"kill", 5, None),
    (b"lease", 28, None),
    (b"linux_immutable", 9, None),
    (b"mac_admin", 33, None),
    (b"mac_override", 32, None),
    (b"mknod", 27, None),
    (b"net_admin", 12, None),
    (b"net_bind_service", 10, None),
    (b"net_broadcast", 11, None),
    (b"net_raw", 13, None),
    (b"perfmon", 38, Some(21)),
    (b"setfcap", 31, None),
    (b"setgid", 6, None),
    (b"setpcap", 8, None),
    (b"setuid", 7, None),
    (b"syslog", 34, None),
    (b"sys_admin", 21, None),
    (b"sys_boot", 22, None),
    (b"sys_chroot", 18, None),
    (b"sys_module", 16, None),
    (b"sys_nice", 23, None),
    (b"sys_pacct", 20, None),
    (b"sys_ptrace", 19, None),
    (b"sys_rawio", 17, None),
    (b"sys_resource", 24, None),
    (b"sys_time", 25, None),
    (b"sys_tty_config", 26, None),
    (b"wake_alarm", 35, None),
];

pub(crate) const RLIMIT_CPU: u32 = 0;
pub(crate) const RLIMIT_FSIZE: u32 = 1;
pub(crate) const RLIMIT_DATA: u32 = 2;
pub(crate) const RLIMIT_STACK: u32 = 3;
pub(crate) const RLIMIT_CORE: u32 = 4;
pub(crate) const RLIMIT_RSS: u32 = 5;
pub(crate) const RLIMIT_NPROC: u32 = 6;
pub(crate) const RLIMIT_NOFILE: u32 = 7;
pub(crate) const RLIMIT_MEMLOCK: u32 = 8;
pub(crate) const RLIMIT_AS: u32 = 9;
pub(crate) const RLIMIT_LOCKS: u32 = 10;
pub(crate) const RLIMIT_SIGPENDING: u32 = 11;
pub(crate) const RLIMIT_MSGQUEUE: u32 = 12;
pub(crate) const RLIMIT_NICE: u32 = 13;
pub(crate) const RLIMIT_RTPRIO: u32 = 14;
pub(crate) const RLIMIT_RTTIME: u32 = 15;
pub(crate) const RLIMIT_COUNT: usize = 16;

pub(crate) fn rlimit(name: &[u8]) -> Option<u32> {
    Some(match name {
        b"cpu" => RLIMIT_CPU,
        b"fsize" => RLIMIT_FSIZE,
        b"data" => RLIMIT_DATA,
        b"stack" => RLIMIT_STACK,
        b"core" => RLIMIT_CORE,
        b"rss" => RLIMIT_RSS,
        b"nofile" | b"ofile" => RLIMIT_NOFILE,
        b"as" => RLIMIT_AS,
        b"nproc" => RLIMIT_NPROC,
        b"memlock" => RLIMIT_MEMLOCK,
        b"locks" => RLIMIT_LOCKS,
        b"sigpending" => RLIMIT_SIGPENDING,
        b"msgqueue" => RLIMIT_MSGQUEUE,
        b"nice" => RLIMIT_NICE,
        b"rtprio" => RLIMIT_RTPRIO,
        b"rttime" => RLIMIT_RTTIME,
        _ => return None,
    })
}

/// Signals as upstream numbers them in policy, which is not the kernel's
/// numbering past the standard ones.
const SIGNALS: &[(&[u8], u32)] = &[
    (b"hup", 1),
    (b"int", 2),
    (b"quit", 3),
    (b"ill", 4),
    (b"trap", 5),
    (b"abrt", 6),
    (b"bus", 7),
    (b"fpe", 8),
    (b"kill", 9),
    (b"usr1", 10),
    (b"segv", 11),
    (b"usr2", 12),
    (b"pipe", 13),
    (b"alrm", 14),
    (b"term", 15),
    (b"stkflt", 16),
    (b"chld", 17),
    (b"cont", 18),
    (b"stop", 19),
    (b"stp", 20),
    (b"tstp", 20),
    (b"ttin", 21),
    (b"ttou", 22),
    (b"urg", 23),
    (b"xcpu", 24),
    (b"xfsz", 25),
    (b"vtalrm", 26),
    (b"prof", 27),
    (b"winch", 28),
    (b"io", 29),
    (b"poll", 29),
    (b"pwr", 30),
    (b"sys", 31),
    (b"emt", 32),
    (b"exists", 35),
];

pub(crate) const MIN_RT_SIGNAL: u32 = 128;
pub(crate) const MAX_RT_SIGNAL: u32 = 32;

/// `rtmin+N` reads N like `strtoul`: leading blanks and a sign are
/// accepted, and anything after the digits is ignored.
pub(crate) fn signal(name: &[u8]) -> Option<u32> {
    if let Some(rest) = name.strip_prefix(b"rtmin+") {
        let n = crate::apparmor::eval::strtoul_prefix(rest)?;
        if n > MAX_RT_SIGNAL as u64 {
            return None;
        }
        return Some(MIN_RT_SIGNAL + n as u32);
    }
    SIGNALS.iter().find(|(n, _)| *n == name).map(|&(_, v)| v)
}

/// Error names upstream accepts for `error=`, which are the names glibc's
/// `errno.h` defines, matched without regard to case.
const ERRNOS: &[(&[u8], u32)] = &[
    (b"EPERM", 1),
    (b"ENOENT", 2),
    (b"ESRCH", 3),
    (b"EINTR", 4),
    (b"EIO", 5),
    (b"ENXIO", 6),
    (b"E2BIG", 7),
    (b"ENOEXEC", 8),
    (b"EBADF", 9),
    (b"ECHILD", 10),
    (b"EAGAIN", 11),
    (b"ENOMEM", 12),
    (b"EACCES", 13),
    (b"EFAULT", 14),
    (b"ENOTBLK", 15),
    (b"EBUSY", 16),
    (b"EEXIST", 17),
    (b"EXDEV", 18),
    (b"ENODEV", 19),
    (b"ENOTDIR", 20),
    (b"EISDIR", 21),
    (b"EINVAL", 22),
    (b"ENFILE", 23),
    (b"EMFILE", 24),
    (b"ENOTTY", 25),
    (b"ETXTBSY", 26),
    (b"EFBIG", 27),
    (b"ENOSPC", 28),
    (b"ESPIPE", 29),
    (b"EROFS", 30),
    (b"EMLINK", 31),
    (b"EPIPE", 32),
    (b"EDOM", 33),
    (b"ERANGE", 34),
    (b"EDEADLK", 35),
    (b"ENAMETOOLONG", 36),
    (b"ENOLCK", 37),
    (b"ENOSYS", 38),
    (b"ENOTEMPTY", 39),
    (b"ELOOP", 40),
    (b"EWOULDBLOCK", 11),
    (b"ENOMSG", 42),
    (b"EIDRM", 43),
    (b"ECHRNG", 44),
    (b"EL2NSYNC", 45),
    (b"EL3HLT", 46),
    (b"EL3RST", 47),
    (b"ELNRNG", 48),
    (b"EUNATCH", 49),
    (b"ENOCSI", 50),
    (b"EL2HLT", 51),
    (b"EBADE", 52),
    (b"EBADR", 53),
    (b"EXFULL", 54),
    (b"ENOANO", 55),
    (b"EBADRQC", 56),
    (b"EBADSLT", 57),
    (b"EDEADLOCK", 35),
    (b"EBFONT", 59),
    (b"ENOSTR", 60),
    (b"ENODATA", 61),
    (b"ETIME", 62),
    (b"ENOSR", 63),
    (b"ENONET", 64),
    (b"ENOPKG", 65),
    (b"EREMOTE", 66),
    (b"ENOLINK", 67),
    (b"EADV", 68),
    (b"ESRMNT", 69),
    (b"ECOMM", 70),
    (b"EPROTO", 71),
    (b"EMULTIHOP", 72),
    (b"EDOTDOT", 73),
    (b"EBADMSG", 74),
    (b"EOVERFLOW", 75),
    (b"ENOTUNIQ", 76),
    (b"EBADFD", 77),
    (b"EREMCHG", 78),
    (b"ELIBACC", 79),
    (b"ELIBBAD", 80),
    (b"ELIBSCN", 81),
    (b"ELIBMAX", 82),
    (b"ELIBEXEC", 83),
    (b"EILSEQ", 84),
    (b"ERESTART", 85),
    (b"ESTRPIPE", 86),
    (b"EUSERS", 87),
    (b"ENOTSOCK", 88),
    (b"EDESTADDRREQ", 89),
    (b"EMSGSIZE", 90),
    (b"EPROTOTYPE", 91),
    (b"ENOPROTOOPT", 92),
    (b"EPROTONOSUPPORT", 93),
    (b"ESOCKTNOSUPPORT", 94),
    (b"EOPNOTSUPP", 95),
    (b"EPFNOSUPPORT", 96),
    (b"EAFNOSUPPORT", 97),
    (b"EADDRINUSE", 98),
    (b"EADDRNOTAVAIL", 99),
    (b"ENETDOWN", 100),
    (b"ENETUNREACH", 101),
    (b"ENETRESET", 102),
    (b"ECONNABORTED", 103),
    (b"ECONNRESET", 104),
    (b"ENOBUFS", 105),
    (b"EISCONN", 106),
    (b"ENOTCONN", 107),
    (b"ESHUTDOWN", 108),
    (b"ETOOMANYREFS", 109),
    (b"ETIMEDOUT", 110),
    (b"ECONNREFUSED", 111),
    (b"EHOSTDOWN", 112),
    (b"EHOSTUNREACH", 113),
    (b"EALREADY", 114),
    (b"EINPROGRESS", 115),
    (b"ESTALE", 116),
    (b"EUCLEAN", 117),
    (b"ENOTNAM", 118),
    (b"ENAVAIL", 119),
    (b"EISNAM", 120),
    (b"EREMOTEIO", 121),
    (b"EDQUOT", 122),
    (b"ENOMEDIUM", 123),
    (b"EMEDIUMTYPE", 124),
    (b"ECANCELED", 125),
    (b"ENOKEY", 126),
    (b"EKEYEXPIRED", 127),
    (b"EKEYREVOKED", 128),
    (b"EKEYREJECTED", 129),
    (b"EOWNERDEAD", 130),
    (b"ENOTRECOVERABLE", 131),
    (b"ERFKILL", 132),
    (b"EHWPOISON", 133),
    (b"ENOTSUP", 95),
];

pub(crate) fn errno(name: &[u8]) -> Option<u32> {
    ERRNOS
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case(name))
        .map(|&(_, v)| v)
}
