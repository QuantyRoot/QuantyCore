//! Patterns of the profile language (`/home/*/**`, `{a,b}`, `[^x]`) to
//! the regular expression notation the automaton builder reads, the way
//! upstream's convert_aaregex_to_pcre does it, checks included.

use crate::apparmor::lexer::escape_seq;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Glob {
    /// Globs never match NUL, so separators between fields cannot be
    /// crossed.
    Default,
    /// Globs match anything except `/`; used for xattr values.
    Null,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PatternType {
    Basic,
    TailGlob,
    Regex,
}

/// Alternations may nest at most this deep, as upstream allows.
pub const MAX_ALT_DEPTH: usize = 50;

/// Converts `aare` and appends the result to `out`. Returns the pattern's
/// type and the offset of its first wildcard (0 when there is none).
pub fn convert(aare: &[u8], glob: Glob, out: &mut Vec<u8>) -> Result<(PatternType, usize), String> {
    let mut ptype = PatternType::Basic;
    let mut first_re: usize = 0;
    let mut escape = false;
    let mut grouping: usize = 0;
    let mut in_class = false;
    let mut counts = [0u32; MAX_ALT_DEPTH];
    let mut i = 0;
    let (one, star, any) = match glob {
        Glob::Default => (&b"[^/\\x00]"[..], &b"[^/\\x00]*"[..], &b"[^\\x00]*"[..]),
        Glob::Null => (&b"[^/]"[..], &b"[^/]*"[..], &b".*"[..]),
    };
    macro_rules! re_pos {
        ($p:expr) => {
            if first_re == 0 {
                first_re = $p;
            }
        };
    }
    while i < aare.len() {
        let c = aare[i];
        match c {
            b'\\' => {
                if escape {
                    out.extend_from_slice(b"\\\\");
                } else {
                    escape = true;
                    i += 1;
                    continue;
                }
            }
            b'*' => {
                if escape {
                    out.extend_from_slice(b"\\*");
                } else {
                    if out.last() == Some(&b'/') {
                        // A star that is a whole path component must match
                        // at least one character, so "/*" is not "/".
                        let mut s = i;
                        while s < aare.len() && aare[s] == b'*' {
                            s += 1;
                        }
                        if s == aare.len() || aare[s] == b'/' {
                            out.extend_from_slice(one);
                        }
                    }
                    if aare.get(i + 1) == Some(&b'*') {
                        re_pos!(i);
                        ptype = if i + 2 == aare.len() && ptype == PatternType::Basic {
                            PatternType::TailGlob
                        } else {
                            PatternType::Regex
                        };
                        out.extend_from_slice(any);
                        i += 1;
                    } else {
                        re_pos!(i);
                        ptype = PatternType::Regex;
                        out.extend_from_slice(star);
                    }
                }
            }
            b'?' => {
                if escape {
                    out.push(b'?');
                } else {
                    re_pos!(i);
                    ptype = PatternType::Regex;
                    out.extend_from_slice(one);
                }
            }
            b'[' => {
                if escape {
                    out.extend_from_slice(b"\\[");
                } else {
                    re_pos!(i);
                    in_class = true;
                    ptype = PatternType::Regex;
                    out.push(b'[');
                }
            }
            b']' => {
                if escape {
                    out.extend_from_slice(b"\\]");
                } else {
                    if !in_class {
                        return Err(
                            "Regex grouping error: Invalid close ], no matching open [ detected"
                                .into(),
                        );
                    }
                    in_class = false;
                    out.push(b']');
                }
            }
            b'{' => {
                if escape {
                    out.extend_from_slice(b"\\{");
                } else if in_class {
                    out.push(b'{');
                } else {
                    re_pos!(i);
                    grouping += 1;
                    if grouping >= MAX_ALT_DEPTH {
                        return Err("Regex grouping error: Exceeded maximum nesting of {}".into());
                    }
                    counts[grouping] = 0;
                    ptype = PatternType::Regex;
                    out.push(b'(');
                }
            }
            b'}' => {
                if escape {
                    out.extend_from_slice(b"\\}");
                } else if in_class {
                    out.push(b'}');
                } else {
                    if counts[grouping] == 0 {
                        return Err(
                            "Regex grouping error: Invalid number of items between {}".into()
                        );
                    }
                    if grouping == 0 {
                        return Err(
                            "Regex grouping error: Invalid close }, no matching open { detected"
                                .into(),
                        );
                    }
                    grouping -= 1;
                    out.push(b')');
                }
            }
            b',' => {
                if escape {
                    if in_class {
                        out.extend_from_slice(b"\\,");
                    } else {
                        out.push(b',');
                    }
                } else if grouping > 0 && !in_class {
                    counts[grouping] += 1;
                    out.push(b'|');
                } else {
                    out.push(b',');
                }
            }
            b'^' | b'$' => {
                if !in_class {
                    out.push(b'\\');
                }
                out.push(c);
            }
            _ => {
                if matches!(c, b'.' | b'+' | b'|' | b'(' | b')') {
                    out.push(b'\\');
                }
                if escape {
                    match escape_seq(aare, i) {
                        Some((_, end)) => {
                            out.push(b'\\');
                            out.extend_from_slice(&aare[i..end]);
                            i = end - 1;
                        }
                        None => out.push(c),
                    }
                } else {
                    out.push(c);
                }
            }
        }
        escape = false;
        i += 1;
    }
    if grouping > 0 || in_class {
        return Err(
            "Regex grouping error: Unclosed grouping or character class, expecting close }".into(),
        );
    }
    if escape {
        return Err("Regex error: trailing '\\' escape character".into());
    }
    Ok((ptype, first_re))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn conv(s: &str) -> Result<(String, PatternType), String> {
        let mut out = Vec::new();
        convert(s.as_bytes(), Glob::Default, &mut out)
            .map(|(t, _)| (String::from_utf8(out).unwrap(), t))
    }

    fn ok(s: &str, want: &str, t: PatternType) {
        assert_eq!(conv(s).unwrap(), (want.to_string(), t), "{s}");
    }

    #[test]
    fn upstream_conversion_examples() {
        use PatternType::*;
        ok("/most/basic/test", "/most/basic/test", Basic);
        assert!(conv("\\").is_err());
        ok("\\\\", "\\\\", Basic);
        ok("\\blort", "blort", Basic);
        ok("*", "[^/\\x00]*", Regex);
        ok("\\*", "\\*", Basic);
        ok("\\?", "?", Basic);
        ok("\\,", ",", Basic);
        ok("^", "\\^", Basic);
        ok(".", "\\.", Basic);
        ok("[blort]", "[blort]", Regex);
        assert!(conv("[blort").is_err());
        assert!(conv("blort]").is_err());
        ok("{alpha,beta}", "(alpha|beta)", Regex);
        assert!(conv("{beta}").is_err());
        assert!(conv("biz{be,ta").is_err());
        assert!(conv("biz,be}ta").is_err());
        assert!(conv("biz{}beta").is_err());
        ok(
            "{{alpha,{blort,nested}},beta}",
            "((alpha|(blort|nested))|beta)",
            Regex,
        );
        ok("/*", "/[^/\\x00][^/\\x00]*", Regex);
        ok("/**", "/[^/\\x00][^\\x00]*", TailGlob);
        ok("/**/blort", "/[^/\\x00][^\\x00]*/blort", Regex);
        ok("\\\\?", "\\\\[^/\\x00]", Regex);
        ok("\\x00", "\\x00", Basic);
        ok("\\d000", "\\d000", Basic);
        ok("b[\\{a\\,b\\}]t", "b[\\{a\\,b\\}]t", Regex);
        let nested = |n: usize| format!("{}a,b{}", "{a".repeat(n), ",b}".repeat(n));
        assert!(conv(&nested(MAX_ALT_DEPTH - 1)).is_ok());
        assert!(conv(&nested(MAX_ALT_DEPTH)).is_err());
    }

    #[test]
    fn null_glob_variant() {
        let mut out = Vec::new();
        convert(b"/foo/**", Glob::Null, &mut out).unwrap();
        assert_eq!(out, b"/foo/[^/].*".to_vec());
    }
}
