//! Matching the name a client asked for against a certificate (RFC 6125),
//! and name constraints (RFC 5280 4.2.1.10).

use super::cert::GeneralName;
use super::der::{tag, Der};

/// What a client asked to connect to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ServerName {
    Dns(String),
    Ip(Vec<u8>),
}

impl ServerName {
    /// A DNS name or an IPv4/IPv6 address. DNS names are lowercased and a
    /// single trailing dot is dropped; anything that is not a valid host
    /// name is refused.
    pub fn parse(s: &str) -> Option<ServerName> {
        if let Ok(ip) = s.parse::<std::net::IpAddr>() {
            return Some(ServerName::Ip(match ip {
                std::net::IpAddr::V4(a) => a.octets().to_vec(),
                std::net::IpAddr::V6(a) => a.octets().to_vec(),
            }));
        }
        let s = s.strip_suffix('.').unwrap_or(s).to_ascii_lowercase();
        valid_dns(&s, false).then_some(ServerName::Dns(s))
    }
}

/// A host name of labels of letters, digits and hyphens (RFC 5280
/// 4.2.1.6 refers to RFC 1034's preferred syntax), each 1 to 63 bytes and not starting or ending with a hyphen. With
/// `wildcard`, the first label may be exactly `*`.
pub fn valid_dns(s: &str, wildcard: bool) -> bool {
    if s.is_empty() || s.len() > 253 {
        return false;
    }
    let labels: Vec<&str> = s.split('.').collect();
    // A name of digits and dots only would be read as an IPv4 address.
    if labels
        .last()
        .is_some_and(|l| l.bytes().all(|b| b.is_ascii_digit()))
    {
        return false;
    }
    labels.iter().enumerate().all(|(i, l)| {
        (wildcard && i == 0 && *l == "*")
            || (!l.is_empty()
                && l.len() <= 63
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'))
    })
}

/// RFC 6125 6.4: exact match, or a wildcard that is the whole leftmost
/// label of a name with at least two more labels, standing for exactly
/// one label. `*.com` and `f*.example.com` match nothing.
pub fn dns_matches(presented: &str, reference: &str) -> bool {
    if !valid_dns(presented, true) {
        return false;
    }
    let presented = presented.strip_suffix('.').unwrap_or(presented);
    if let Some(base) = presented.strip_prefix("*.") {
        if base.split('.').count() < 2 {
            return false;
        }
        match reference.split_once('.') {
            Some((first, rest)) => !first.is_empty() && rest == base,
            None => false,
        }
    } else {
        presented == reference
    }
}

pub fn name_matches(san: &[GeneralName], name: &ServerName) -> bool {
    san.iter().any(|g| match (g, name) {
        (GeneralName::Dns(p), ServerName::Dns(r)) => dns_matches(p, r),
        (GeneralName::Ip(p), ServerName::Ip(r)) => p == r,
        _ => false,
    })
}

/// Whether DNS name `name` is inside the subtree `base`: equal to it or
/// below it at a label boundary. A base with a leading dot admits only
/// names below it. An empty base admits everything.
fn dns_in_subtree(name: &str, base: &str) -> bool {
    if base.is_empty() {
        return true;
    }
    let name = name
        .strip_prefix("*.")
        .map(|r| format!("x.{r}"))
        .unwrap_or_else(|| name.to_string());
    if let Some(b) = base.strip_prefix('.') {
        return name.len() > b.len()
            && name.ends_with(b)
            && name.as_bytes()[name.len() - b.len() - 1] == b'.';
    }
    name == base
        || (name.len() > base.len()
            && name.ends_with(base)
            && name.as_bytes()[name.len() - base.len() - 1] == b'.')
}

/// Whether a wildcard name could stand for a name inside `base`, for
/// excluded subtrees: `*.example.com` covers `bad.example.com`.
fn wildcard_reaches(name: &str, base: &str) -> bool {
    match name.strip_prefix("*.") {
        Some(rest) => {
            dns_in_subtree(rest, base)
                || base
                    .trim_start_matches('.')
                    .split_once('.')
                    .is_some_and(|(_, up)| up == rest)
        }
        None => false,
    }
}

fn ip_in_subtree(ip: &[u8], constraint: &[u8]) -> Option<bool> {
    let n = ip.len();
    if constraint.len() != 2 * n {
        return if constraint.len() == 8 || constraint.len() == 32 {
            Some(false)
        } else {
            None
        };
    }
    let (addr, mask) = constraint.split_at(n);
    // A mask must be contiguous ones followed by zeros.
    let bits: Vec<bool> = mask
        .iter()
        .flat_map(|b| (0..8).map(move |i| b & (0x80 >> i) != 0))
        .collect();
    if bits.windows(2).any(|w| !w[0] && w[1]) {
        return None;
    }
    Some(
        ip.iter()
            .zip(addr)
            .zip(mask)
            .all(|((i, a), m)| i & m == a & m),
    )
}

/// The RDNs of a Name, each as its DER, for prefix comparison.
fn rdns(name: &[u8]) -> Option<Vec<&[u8]>> {
    let mut d = Der::new(name);
    let mut seq = d.sequence().ok()?;
    let mut out = Vec::new();
    while !seq.is_empty() {
        let (_, w) = seq.expect_whole(tag::SET).ok()?;
        out.push(w);
    }
    Some(out)
}

fn dn_in_subtree(name: &[u8], base: &[u8]) -> bool {
    match (rdns(name), rdns(base)) {
        (Some(n), Some(b)) => n.len() >= b.len() && n[..b.len()] == b[..],
        _ => false,
    }
}

/// Checks the names of one certificate below a CA against the CA's
/// constraints. `subject` is the certificate's subject Name, which a
/// directoryName constraint applies to. Constraint kinds this does not
/// evaluate (email, URI and others) fail closed when the certificate
/// carries a name of that kind.
pub fn check_constraints(
    permitted: Option<&[GeneralName]>,
    excluded: &[GeneralName],
    names: &[GeneralName],
    subject: &[u8],
    check_subject: bool,
) -> Result<(), &'static str> {
    let mut all: Vec<GeneralName> = names.to_vec();
    let empty_subject = rdns(subject).is_none_or(|r| r.is_empty());
    if check_subject && !empty_subject {
        all.push(GeneralName::Directory(subject.to_vec()));
    }
    for n in &all {
        let same_kind: Vec<&GeneralName> = permitted
            .unwrap_or(&[])
            .iter()
            .filter(|c| {
                std::mem::discriminant(*c) == std::mem::discriminant(n) && kind_of(c) == kind_of(n)
            })
            .collect();
        for c in excluded {
            if kind_of(c) != kind_of(n) {
                continue;
            }
            let hit = match (c, n) {
                (GeneralName::Dns(b), GeneralName::Dns(x)) => {
                    dns_in_subtree(x, b) || wildcard_reaches(x, b)
                }
                (GeneralName::Ip(b), GeneralName::Ip(x)) => {
                    ip_in_subtree(x, b).ok_or("malformed IP constraint")?
                }
                (GeneralName::Directory(b), GeneralName::Directory(x)) => dn_in_subtree(x, b),
                _ => return Err("name constraint of a kind not evaluated"),
            };
            if hit {
                return Err("name in an excluded subtree");
            }
        }
        if permitted.is_some() && !same_kind.is_empty() {
            let mut ok = false;
            for c in same_kind {
                ok |= match (c, n) {
                    (GeneralName::Dns(b), GeneralName::Dns(x)) => dns_in_subtree(x, b),
                    (GeneralName::Ip(b), GeneralName::Ip(x)) => {
                        ip_in_subtree(x, b).ok_or("malformed IP constraint")?
                    }
                    (GeneralName::Directory(b), GeneralName::Directory(x)) => dn_in_subtree(x, b),
                    _ => return Err("name constraint of a kind not evaluated"),
                };
            }
            if !ok {
                return Err("name outside the permitted subtrees");
            }
        }
        if let GeneralName::Other(_) = n {
            let constrained = permitted
                .unwrap_or(&[])
                .iter()
                .chain(excluded)
                .any(|c| kind_of(c) == kind_of(n));
            if constrained {
                return Err("name constraint of a kind not evaluated");
            }
        }
    }
    Ok(())
}

fn kind_of(g: &GeneralName) -> u8 {
    match g {
        GeneralName::Dns(_) => 2,
        GeneralName::Ip(_) => 7,
        GeneralName::Directory(_) => 4,
        GeneralName::Other(t) => *t,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wildcards_per_rfc_6125() {
        assert!(dns_matches("*.example.com", "www.example.com"));
        assert!(!dns_matches("*.example.com", "example.com"));
        assert!(!dns_matches("*.example.com", "a.b.example.com"));
        assert!(!dns_matches("*.com", "example.com"));
        assert!(!dns_matches("w*.example.com", "www.example.com"));
        assert!(!dns_matches("www.*.com", "www.example.com"));
        assert!(dns_matches("example.com", "example.com"));
        assert!(!dns_matches("example.com", "www.example.com"));
    }

    #[test]
    fn subtrees_at_label_boundaries() {
        assert!(dns_in_subtree("example.com", "example.com"));
        assert!(dns_in_subtree("a.example.com", "example.com"));
        assert!(!dns_in_subtree("badexample.com", "example.com"));
        assert!(!dns_in_subtree("example.com", ".example.com"));
        assert!(dns_in_subtree("a.example.com", ".example.com"));
        assert_eq!(
            ip_in_subtree(&[10, 1, 2, 3], &[10, 0, 0, 0, 255, 0, 0, 0]),
            Some(true)
        );
        assert_eq!(
            ip_in_subtree(&[11, 1, 2, 3], &[10, 0, 0, 0, 255, 0, 0, 0]),
            Some(false)
        );
        assert_eq!(
            ip_in_subtree(&[10, 1, 2, 3], &[10, 0, 0, 0, 255, 0, 255, 0]),
            None
        );
    }

    #[test]
    fn server_names() {
        assert_eq!(
            ServerName::parse("Example.COM."),
            Some(ServerName::Dns("example.com".into()))
        );
        assert_eq!(
            ServerName::parse("10.0.0.1"),
            Some(ServerName::Ip(vec![10, 0, 0, 1]))
        );
        assert_eq!(ServerName::parse("bad..name"), None);
        assert_eq!(ServerName::parse("-x.example"), None);
        assert_eq!(ServerName::parse("1.2.3.256"), None);
    }
}
