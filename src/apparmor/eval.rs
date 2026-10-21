//! Variables and conditions: the symbol table, set variables and their
//! expansion, boolean variables, and `if` expressions.
//!
//! Upstream evaluates these while it parses, in file order, and caches a
//! set variable's expansion the first time anything asks for it. A `+=`
//! after that first use does not change what later rules see. The same
//! cache is kept here, because profiles can tell the difference.

use std::collections::{BTreeSet, HashMap};

use super::ast::{AssignOp, CmpOp, Expr, Operand};

/// Expanding one set variable may produce at most this many values and
/// this many bytes. Sets that refer to sets multiply, and upstream runs
/// out of memory on the cases in its own suite that do this on purpose.
pub const MAX_EXPANSION_VALUES: usize = 1 << 16;
pub const MAX_EXPANSION_BYTES: usize = 16 << 20;
/// Variables may refer to variables this deep.
pub const MAX_REFERENCE_DEPTH: usize = 256;

#[derive(Debug, Clone)]
pub(crate) enum Value {
    Bool(bool),
    Set {
        values: BTreeSet<Vec<u8>>,
        expanded: Option<BTreeSet<Vec<u8>>>,
    },
}

#[derive(Debug, Clone)]
pub(crate) struct Var {
    pub value: Value,
    expanding: bool,
}

#[derive(Default, Debug, Clone)]
pub(crate) struct Symtab {
    vars: HashMap<Vec<u8>, Var>,
}

/// Why a variable name is not one. A comma is told apart because a name
/// like `@{a,b}` in a rule is old alternation syntax, not an error there.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum BadName {
    NoPrefix,
    NoClosingBrace,
    BadStart,
    BadChar,
    Comma,
}

/// Strips `@`, `$` and braces, and checks what is left: a letter, then
/// letters, digits and underscores.
pub(crate) fn var_name(var: &[u8]) -> Result<&[u8], BadName> {
    let rest = match var.first() {
        Some(b'@') | Some(b'$') => &var[1..],
        _ => return Err(BadName::NoPrefix),
    };
    let name = match rest.first() {
        Some(b'{') => {
            if rest.len() < 2 || rest[rest.len() - 1] != b'}' {
                return Err(BadName::NoClosingBrace);
            }
            &rest[1..rest.len() - 1]
        }
        _ => rest,
    };
    for (i, &c) in name.iter().enumerate() {
        if i == 0 || c == name[0] {
            if !c.is_ascii_alphabetic() {
                return Err(BadName::BadStart);
            }
        } else if !(c == b'_' || c.is_ascii_alphanumeric()) {
            return Err(if c == b',' {
                BadName::Comma
            } else {
                BadName::BadChar
            });
        }
    }
    if name.is_empty() {
        return Err(BadName::BadStart);
    }
    Ok(name)
}

/// The first `@{...}` in `s` that is not escaped, as prefix, variable
/// (with its `@{` and `}`) and suffix.
pub(crate) fn split_var(s: &[u8]) -> Option<(&[u8], &[u8], &[u8])> {
    let mut escape = false;
    let mut start = None;
    let mut i = 0;
    while i < s.len() {
        match s[i] {
            b'\\' => escape = !escape,
            b'@' => {
                if escape {
                    escape = false;
                } else if s.get(i + 1) == Some(&b'{') {
                    // Upstream steps past the brace and then once more,
                    // so the first character of the name is never looked
                    // at: "@{}" is not a variable, "@{}}" is.
                    start = Some(i);
                    i += 3;
                    continue;
                }
            }
            b'}' => {
                if escape {
                    escape = false;
                } else if let Some(st) = start {
                    return Some((&s[..st], &s[st..=i], &s[i + 1..]));
                }
            }
            _ => escape = false,
        }
        i += 1;
    }
    None
}

/// `strtoul` on the start of `s`: leading blanks, an optional sign, then
/// decimal digits; no digits reads as zero, a minus wraps around.
pub(crate) fn strtoul_prefix(s: &[u8]) -> Option<u64> {
    let mut i = 0;
    while i < s.len() && (s[i] == b' ' || (9..=13).contains(&s[i])) {
        i += 1;
    }
    let mut neg = false;
    if i < s.len() && (s[i] == b'+' || s[i] == b'-') {
        neg = s[i] == b'-';
        i += 1;
    }
    let mut v: u64 = 0;
    while i < s.len() && s[i].is_ascii_digit() {
        v = v.saturating_mul(10).saturating_add((s[i] - b'0') as u64);
        i += 1;
    }
    Some(if neg { v.wrapping_neg() } else { v })
}

/// `strtol(s, &end, 0)`: the value, whether the whole string was read,
/// and whether it overflowed. Leading blanks and a sign are accepted, and
/// `0x` or a leading `0` choose hex or octal.
pub(crate) fn strtol0(s: &[u8]) -> (i64, bool, bool) {
    let mut i = 0;
    while i < s.len() && (s[i] == b' ' || (9..=13).contains(&s[i])) {
        i += 1;
    }
    let mut neg = false;
    if i < s.len() && (s[i] == b'+' || s[i] == b'-') {
        neg = s[i] == b'-';
        i += 1;
    }
    let mut base = 10u32;
    let digits_start;
    if s[i..].len() >= 2
        && s[i] == b'0'
        && (s[i + 1] | 0x20) == b'x'
        && s.get(i + 2).is_some_and(|c| c.is_ascii_hexdigit())
    {
        base = 16;
        i += 2;
        digits_start = i;
    } else if s.get(i) == Some(&b'0') {
        base = 8;
        digits_start = i;
    } else {
        digits_start = i;
    }
    let mut v: i128 = 0;
    let mut overflow = false;
    while i < s.len() {
        let Some(d) = (s[i] as char).to_digit(base) else {
            break;
        };
        v = v * base as i128 + d as i128;
        if v > i64::MAX as i128 + 1 {
            overflow = true;
            v = i64::MAX as i128 + 1;
        }
        i += 1;
    }
    if i == digits_start {
        return (0, false, false);
    }
    let v = if neg { -v } else { v };
    let (v, of) = if v > i64::MAX as i128 {
        (i64::MAX, true)
    } else if v < i64::MIN as i128 {
        (i64::MIN, true)
    } else {
        (v as i64, false)
    };
    (v, i == s.len(), overflow || of)
}

fn too_large(values: &BTreeSet<Vec<u8>>) -> bool {
    values.len() > MAX_EXPANSION_VALUES
        || values.iter().map(|v| v.len()).sum::<usize>() > MAX_EXPANSION_BYTES
}

impl Symtab {
    fn insert(&mut self, name: Vec<u8>, value: Value) -> Result<(), String> {
        if self.vars.contains_key(&name) {
            return Err(format!(
                "'{}' is already defined",
                String::from_utf8_lossy(&name)
            ));
        }
        self.vars.insert(
            name,
            Var {
                value,
                expanding: false,
            },
        );
        Ok(())
    }

    pub(crate) fn remove(&mut self, name: &[u8]) -> Option<Var> {
        self.vars.remove(name)
    }

    pub(crate) fn restore(&mut self, name: &[u8], var: Option<Var>) {
        self.vars.remove(name);
        if let Some(v) = var {
            self.vars.insert(name.to_vec(), v);
        }
    }

    /// Defines a set variable from a processed name, for the variables
    /// the compiler sets per profile.
    pub(crate) fn define_set(&mut self, name: &[u8], value: Vec<u8>) -> Result<(), String> {
        let mut values = BTreeSet::new();
        values.insert(value);
        self.insert(
            name.to_vec(),
            Value::Set {
                values,
                expanded: None,
            },
        )
    }

    /// A set variable assignment from the preamble.
    pub(crate) fn assign_set(
        &mut self,
        var: &[u8],
        op: AssignOp,
        values: &[Vec<u8>],
    ) -> Result<(), String> {
        let shown = String::from_utf8_lossy(var);
        let name = var_name(var)
            .map_err(|_| format!("invalid variable name '{shown}'"))?
            .to_vec();
        let set: BTreeSet<Vec<u8>> = values.iter().cloned().collect();
        match op {
            AssignOp::Add => match self.vars.get_mut(&name) {
                Some(Var {
                    value: Value::Set { values, .. },
                    ..
                }) => {
                    values.extend(set);
                    Ok(())
                }
                _ => Err(format!(
                    "variable {shown} was not previously declared, but is being assigned additional values"
                )),
            },
            AssignOp::Override => {
                self.vars.remove(&name);
                self.insert(
                    name,
                    Value::Set {
                        values: set,
                        expanded: None,
                    },
                )
            }
            AssignOp::Set | AssignOp::SetIfUnset => {
                let r = self.insert(
                    name,
                    Value::Set {
                        values: set,
                        expanded: None,
                    },
                );
                if op == AssignOp::Set && r.is_err() {
                    return Err(format!("variable {shown} was previously declared"));
                }
                Ok(())
            }
        }
    }

    /// A boolean variable assignment from the preamble. The expression is
    /// evaluated now, as upstream does.
    pub(crate) fn assign_bool(
        &mut self,
        var: &[u8],
        op: AssignOp,
        expr: &Expr,
    ) -> Result<(), String> {
        let shown = String::from_utf8_lossy(var);
        if op == AssignOp::Add {
            return Err("Invalid assignment += not allowed with boolean variables".into());
        }
        let value = self.eval(expr)?;
        let name = var_name(var)
            .map_err(|_| format!("invalid variable name '{shown}'"))?
            .to_vec();
        if op == AssignOp::Override {
            self.vars.remove(&name);
        }
        let r = self.insert(name, Value::Bool(value));
        if op == AssignOp::Set && r.is_err() {
            return Err(format!("variable {shown} was previously declared"));
        }
        Ok(())
    }

    /// Expands a set variable's values through the variables they refer
    /// to, once, and keeps the result.
    pub(crate) fn expand(&mut self, name: &[u8]) -> Result<(), String> {
        self.expand_depth(name, 0)
    }

    fn expand_depth(&mut self, name: &[u8], depth: usize) -> Result<(), String> {
        if depth > MAX_REFERENCE_DEPTH {
            return Err("variables refer to each other too deeply".into());
        }
        let work: Vec<Vec<u8>> = match self.vars.get(name) {
            Some(Var {
                value: Value::Bool(_),
                ..
            }) => {
                return Err(format!(
                    "Referenced variable {} is a boolean used in set context",
                    String::from_utf8_lossy(name)
                ))
            }
            Some(Var {
                value: Value::Set {
                    expanded: Some(_), ..
                },
                ..
            }) => return Ok(()),
            Some(Var {
                value: Value::Set { values, .. },
                ..
            }) => values.iter().cloned().collect(),
            None => {
                return Err(format!(
                    "Failed to find declaration for: {}",
                    String::from_utf8_lossy(name)
                ))
            }
        };
        self.set_expanding(name, true);
        let result = self.expand_work(name, work, depth);
        self.set_expanding(name, false);
        let expanded = result?;
        if let Some(Var {
            value: Value::Set { expanded: e, .. },
            ..
        }) = self.vars.get_mut(name)
        {
            *e = Some(expanded);
        }
        Ok(())
    }

    fn set_expanding(&mut self, name: &[u8], on: bool) {
        if let Some(v) = self.vars.get_mut(name) {
            v.expanding = on;
        }
    }

    fn expand_work(
        &mut self,
        name: &[u8],
        mut work: Vec<Vec<u8>>,
        depth: usize,
    ) -> Result<BTreeSet<Vec<u8>>, String> {
        let mut out = BTreeSet::new();
        let mut i = 0;
        while i < work.len() {
            let value = work[i].clone();
            i += 1;
            let Some((prefix, var, suffix)) = split_var(&value) else {
                out.insert(value);
                if too_large(&out) {
                    return Err("variable expansion too large".into());
                }
                continue;
            };
            let shown = String::from_utf8_lossy(var).into_owned();
            let Ok(refname) = var_name(var) else {
                return Err(format!("Failed to find declaration for: {shown}"));
            };
            let refname = refname.to_vec();
            match self.vars.get(&refname) {
                None => return Err(format!("Failed to find declaration for: {shown}")),
                Some(v) if v.expanding => {
                    return Err(format!(
                        "Variable @{{{}}} is referenced recursively (by @{{{}}})",
                        String::from_utf8_lossy(&refname),
                        String::from_utf8_lossy(name)
                    ))
                }
                Some(_) => {}
            }
            self.expand_depth(&refname, depth + 1)?;
            let Some(Var {
                value:
                    Value::Set {
                        expanded: Some(refs),
                        ..
                    },
                ..
            }) = self.vars.get(&refname)
            else {
                return Err(format!("Failed to find declaration for: {shown}"));
            };
            for r in refs {
                let mut v = prefix.to_vec();
                v.extend_from_slice(r);
                v.extend_from_slice(suffix);
                work.push(v);
            }
            if work.len() - i > MAX_EXPANSION_VALUES
                || work[i..].iter().map(|w| w.len()).sum::<usize>() > MAX_EXPANSION_BYTES
            {
                return Err("variable expansion too large".into());
            }
        }
        Ok(out)
    }

    /// The expanded values of a set variable named as written (`@{x}`).
    fn set_values(&mut self, var: &[u8]) -> Result<BTreeSet<Vec<u8>>, String> {
        let shown = String::from_utf8_lossy(var).into_owned();
        let name = var_name(var).map(|n| n.to_vec()).unwrap_or_default();
        match self.vars.get(&name) {
            Some(Var {
                value: Value::Set { .. },
                ..
            }) => {}
            _ => return Err(format!("Failed to find declaration for: {shown}")),
        }
        self.expand(&name)?;
        match self.vars.get(&name) {
            Some(Var {
                value: Value::Set {
                    expanded: Some(e), ..
                },
                ..
            }) => Ok(e.clone()),
            _ => Err(format!("Failed to find declaration for: {shown}")),
        }
    }

    /// Replaces each variable in a rule's string with an alternation of
    /// its values, `{a,b}`, as upstream does before the pattern is
    /// compiled. Next to a slash, the values lose their own slashes on
    /// that side, so `/@{HOME}/` with `/home/` does not become `//home//`.
    pub(crate) fn expand_alternation(&mut self, s: &[u8]) -> Result<Vec<u8>, String> {
        let mut out = Vec::new();
        let mut rest = s.to_vec();
        loop {
            let Some((prefix, var, suffix)) = split_var(&rest) else {
                out.extend_from_slice(&rest);
                return Ok(out);
            };
            match var_name(var) {
                Ok(_) => {}
                Err(BadName::Comma) => {
                    out.extend_from_slice(&rest);
                    return Ok(out);
                }
                Err(_) => {
                    return Err(format!(
                        "Variable '{}' contains invalid characters or does not start with a letter",
                        String::from_utf8_lossy(var)
                    ))
                }
            }
            let trim_leading = prefix.last() == Some(&b'/') && prefix.iter().any(|&c| c != b'/');
            let trim_trailing = suffix.first() == Some(&b'/');
            let values = self.set_values(var)?;
            let mut alt = Vec::new();
            if values.len() > 1 {
                alt.push(b'{');
            }
            for (n, v) in values.iter().enumerate() {
                let mut v: &[u8] = v;
                if trim_leading {
                    let k = v.iter().position(|&c| c != b'/').unwrap_or(v.len());
                    v = &v[k..];
                }
                if trim_trailing {
                    let k = v.iter().rposition(|&c| c != b'/').map_or(0, |k| k + 1);
                    v = &v[..k];
                }
                if n > 0 {
                    alt.push(b',');
                }
                alt.extend_from_slice(v);
            }
            if values.len() > 1 {
                alt.push(b'}');
            }
            if out.len() + prefix.len() + alt.len() + suffix.len() > MAX_EXPANSION_BYTES {
                return Err("variable expansion too large".into());
            }
            out.extend_from_slice(prefix);
            alt.extend_from_slice(suffix);
            rest = alt;
        }
    }

    fn operand_set(&mut self, op: &Operand) -> Result<BTreeSet<Vec<u8>>, String> {
        if var_name(&op.text).is_err() {
            let mut s = BTreeSet::new();
            s.insert(op.text.clone());
            return Ok(s);
        }
        let name = var_name(&op.text).unwrap_or_default().to_vec();
        if !self.vars.contains_key(&name) {
            return Err(format!(
                "Error retrieving variable {}",
                String::from_utf8_lossy(&op.text)
            ));
        }
        self.expand(&name)?;
        match self.vars.get(&name) {
            Some(Var {
                value: Value::Set {
                    expanded: Some(e), ..
                },
                ..
            }) => Ok(e.clone()),
            _ => Err(format!(
                "Error retrieving variable {}",
                String::from_utf8_lossy(&op.text)
            )),
        }
    }

    /// Evaluates a condition. Both sides of `and` and `or` are evaluated,
    /// as upstream reduces both before combining them, so an error on
    /// either side is an error.
    pub(crate) fn eval(&mut self, e: &Expr) -> Result<bool, String> {
        match e {
            Expr::Or(list) => {
                let mut any = false;
                for e in list {
                    any |= self.eval(e)?;
                }
                Ok(any)
            }
            Expr::And(list) => {
                let mut all = true;
                for e in list {
                    all &= self.eval(e)?;
                }
                Ok(all)
            }
            Expr::Not(a) => Ok(!self.eval(a)?),
            Expr::BoolVar(v, _) => {
                let name = var_name(v).unwrap_or_default();
                match self.vars.get(name) {
                    Some(Var {
                        value: Value::Bool(b),
                        ..
                    }) => Ok(*b),
                    _ => Err(format!(
                        "Unset boolean variable {} used in if-expression",
                        String::from_utf8_lossy(v)
                    )),
                }
            }
            Expr::Defined(v, _) => {
                let name = var_name(v).unwrap_or_default().to_vec();
                match self.vars.get(&name) {
                    Some(Var {
                        value: Value::Set { .. },
                        ..
                    }) => {
                        let _ = self.expand(&name);
                        Ok(true)
                    }
                    _ => Ok(false),
                }
            }
            Expr::Value(op) => {
                if op.text.eq_ignore_ascii_case(b"true") {
                    Ok(true)
                } else if op.text.eq_ignore_ascii_case(b"false") {
                    Ok(false)
                } else {
                    Err(format!(
                        "Invalid boolean : '{}' is not true or false",
                        String::from_utf8_lossy(&op.text)
                    ))
                }
            }
            Expr::Cmp(op, l, r) => {
                let lhs = self.operand_set(l)?;
                let rhs = self.operand_set(r)?;
                match op {
                    CmpOp::In => return Ok(lhs.is_subset(&rhs)),
                    CmpOp::Eq => return Ok(lhs == rhs),
                    CmpOp::Ne => return Ok(lhs != rhs),
                    _ => {}
                }
                let num = |s: &BTreeSet<Vec<u8>>| -> Result<Option<i64>, String> {
                    if s.len() != 1 {
                        return Ok(None);
                    }
                    let v = s.iter().next().unwrap();
                    if v.is_empty() {
                        return Ok(None);
                    }
                    let (n, whole, overflow) = strtol0(v);
                    if overflow {
                        return Err("Value out of valid range".into());
                    }
                    Ok(whole.then_some(n))
                };
                let (ln, rn) = (num(&lhs)?, num(&rhs)?);
                let ord = match (ln, rn) {
                    (Some(a), Some(b)) => a.cmp(&b),
                    (None, None) => lhs.iter().cmp(rhs.iter()),
                    _ => return Err("Can only compare numbers with numbers".into()),
                };
                Ok(match op {
                    CmpOp::Gt => ord.is_gt(),
                    CmpOp::Ge => ord.is_ge(),
                    CmpOp::Lt => ord.is_lt(),
                    _ => ord.is_le(),
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(t: &mut Symtab, var: &str, vals: &[&str]) {
        let v: Vec<Vec<u8>> = vals.iter().map(|s| s.as_bytes().to_vec()).collect();
        t.assign_set(var.as_bytes(), AssignOp::Set, &v).unwrap();
    }

    #[test]
    fn expansion_is_a_cross_product_and_is_cached() {
        let mut t = Symtab::default();
        set(&mut t, "@{A}", &["a", "b"]);
        set(&mut t, "@{B}", &["@{A}/@{A}"]);
        assert_eq!(
            t.expand_alternation(b"/x/@{B}").unwrap(),
            b"/x/{a/a,a/b,b/a,b/b}".to_vec()
        );
        t.assign_set(b"@{A}", AssignOp::Add, &[b"c".to_vec()])
            .unwrap();
        assert_eq!(t.expand_alternation(b"@{A}").unwrap(), b"{a,b}".to_vec());
    }

    #[test]
    fn slashes_next_to_a_variable_are_not_doubled() {
        let mut t = Symtab::default();
        set(&mut t, "@{HOME}", &["/home/", "/root/"]);
        assert_eq!(
            t.expand_alternation(b"/x/@{HOME}/y").unwrap(),
            b"/x/{home,root}/y".to_vec()
        );
        assert_eq!(
            t.expand_alternation(b"@{HOME}/y").unwrap(),
            b"{/home,/root}/y".to_vec()
        );
    }

    #[test]
    fn recursion_and_explosion_are_errors() {
        let mut t = Symtab::default();
        set(&mut t, "@{A}", &["@{B}"]);
        set(&mut t, "@{B}", &["@{A}"]);
        assert!(t
            .expand_alternation(b"@{A}")
            .unwrap_err()
            .contains("recursively"));
        let mut t = Symtab::default();
        set(
            &mut t,
            "@{X}",
            &["0", "1", "2", "3", "4", "5", "6", "7", "8", "9"],
        );
        set(&mut t, "@{Y}", &["@{X}@{X}@{X}@{X}@{X}@{X}"]);
        assert!(t
            .expand_alternation(b"@{Y}")
            .unwrap_err()
            .contains("too large"));
    }

    #[test]
    fn a_comma_in_a_variable_is_left_as_written() {
        let mut t = Symtab::default();
        assert_eq!(
            t.expand_alternation(b"/@{a,b}").unwrap(),
            b"/@{a,b}".to_vec()
        );
    }

    #[test]
    fn numbers_compare_as_numbers_and_sets_as_sets() {
        assert_eq!(strtol0(b"0x10"), (16, true, false));
        assert_eq!(strtol0(b"010"), (8, true, false));
        assert_eq!(strtol0(b"12a"), (12, false, false));
        assert!(strtol0(b"99999999999999999999").2);
    }
}
