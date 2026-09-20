//! Pure, network-free parsing/validation of SPF, DMARC, and DKIM TXT
//! record *content* — the real DNS lookups that produce this content
//! live in `main.rs`.

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecordStatus {
    Missing,
    Invalid(String),
    Valid(String),
}

/// A real SPF record starts with `v=spf1` and is a space-separated list
/// of mechanisms (`ip4:`, `ip6:`, `a`, `mx`, `include:`, `exists:`, a
/// bare `all`) each optionally prefixed with a qualifier (`+`/`-`/`~`/
/// `?`). This checks the `v=spf1` prefix and that every subsequent
/// token is a recognized mechanism shape — not full RFC 7208 grammar,
/// but enough to catch a typo'd or truncated record.
pub fn validate_spf(txt_records: &[String]) -> RecordStatus {
    let candidates: Vec<&String> = txt_records
        .iter()
        .filter(|r| r.starts_with("v=spf1"))
        .collect();
    match candidates.as_slice() {
        [] => RecordStatus::Missing,
        [one] => {
            for token in one.split_whitespace().skip(1) {
                if !is_valid_spf_mechanism(token) {
                    return RecordStatus::Invalid(format!("unrecognized mechanism '{token}'"));
                }
            }
            RecordStatus::Valid((*one).clone())
        }
        _ => RecordStatus::Invalid(format!(
            "{} separate v=spf1 records found — RFC 7208 requires exactly one",
            candidates.len()
        )),
    }
}

fn is_valid_spf_mechanism(token: &str) -> bool {
    let token = token.trim_start_matches(['+', '-', '~', '?']);
    // A modifier (`redirect=`, `exp=`, or any vendor-specific
    // `name=value` — RFC 7208 requires unrecognized modifiers to be
    // silently accepted, not rejected) uses `=`, never `:`. Only read a
    // token as a modifier if `=` appears before any `:`, so
    // `ip4:1.2.3.4` is never misread as one.
    let colon_pos = token.find(':');
    if let Some(eq_pos) = token.find('=') {
        if colon_pos.is_none_or(|c| eq_pos < c) {
            let name = &token[..eq_pos];
            return !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-');
        }
    }
    let (name, _) = token.split_once(':').unwrap_or((token, ""));
    let (name, _) = name.split_once('/').unwrap_or((name, ""));
    matches!(
        name,
        "a" | "mx" | "ptr" | "ip4" | "ip6" | "include" | "exists" | "all"
    )
}

/// A real DMARC record starts with `v=DMARC1` and must carry a `p=`
/// (policy) tag whose value is `none`, `quarantine`, or `reject`.
pub fn validate_dmarc(txt_records: &[String]) -> RecordStatus {
    let candidates: Vec<&String> = txt_records
        .iter()
        .filter(|r| r.starts_with("v=DMARC1"))
        .collect();
    match candidates.as_slice() {
        [] => RecordStatus::Missing,
        [one] => match tag_value(one, "p") {
            Some(p) if matches!(p.as_str(), "none" | "quarantine" | "reject") => {
                RecordStatus::Valid((*one).clone())
            }
            Some(p) => RecordStatus::Invalid(format!("p={p} is not none/quarantine/reject")),
            None => RecordStatus::Invalid("missing required p= tag".to_string()),
        },
        _ => RecordStatus::Invalid(format!(
            "{} separate v=DMARC1 records found — only one is valid",
            candidates.len()
        )),
    }
}

/// A real DKIM record either has no `v=` tag (RFC 6376 says `DKIM1` is
/// the implied default) or an explicit `v=DKIM1`, and must carry a
/// non-empty `p=` tag (the base64 public key — empty `p=` is DKIM's own
/// documented "this key has been revoked" convention, not a real key).
pub fn validate_dkim(txt_records: &[String]) -> RecordStatus {
    let candidates: Vec<&String> = txt_records
        .iter()
        .filter(|r| {
            let v = tag_value(r, "v");
            v.is_none() || v.as_deref() == Some("DKIM1")
        })
        .filter(|r| tag_value(r, "p").is_some())
        .collect();
    match candidates.as_slice() {
        [] => RecordStatus::Missing,
        [one] => match tag_value(one, "p") {
            Some(p) if p.is_empty() => {
                RecordStatus::Invalid("p= is empty — this key has been revoked".to_string())
            }
            Some(_) => RecordStatus::Valid((*one).clone()),
            None => RecordStatus::Missing,
        },
        _ => RecordStatus::Invalid(format!(
            "{} candidate DKIM records found at this selector",
            candidates.len()
        )),
    }
}

/// Extracts `tag`'s value from a `;`-separated `tag=value` record body,
/// e.g. `tag_value("v=DMARC1; p=reject; pct=100", "p")` returns
/// `Some("reject")`.
fn tag_value(record: &str, tag: &str) -> Option<String> {
    record.split(';').find_map(|part| {
        let part = part.trim();
        let (k, v) = part.split_once('=')?;
        if k.trim() == tag {
            Some(v.trim().to_string())
        } else {
            None
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &str) -> String {
        v.to_string()
    }

    #[test]
    fn missing_spf_when_no_record_starts_with_v_spf1() {
        assert_eq!(validate_spf(&[s("something else")]), RecordStatus::Missing);
        assert_eq!(validate_spf(&[]), RecordStatus::Missing);
    }

    #[test]
    fn valid_realistic_spf_record() {
        let r = s("v=spf1 ip4:203.0.113.0/24 include:_spf.google.com ~all");
        assert_eq!(
            validate_spf(std::slice::from_ref(&r)),
            RecordStatus::Valid(r)
        );
    }

    #[test]
    fn spf_with_unrecognized_mechanism_is_invalid() {
        match validate_spf(&[s("v=spf1 bogus:thing ~all")]) {
            RecordStatus::Invalid(msg) => assert!(msg.contains("bogus:thing")),
            other => panic!("expected Invalid, got {other:?}"),
        }
    }

    #[test]
    fn spf_redirect_modifier_uses_equals_not_colon() {
        // A real bug caught live against iana.org's actual SPF record:
        // `redirect=icann.org` was misread as an unrecognized mechanism
        // because the parser only split on `:`, never `=`.
        let r = s("v=spf1 redirect=icann.org");
        assert_eq!(
            validate_spf(std::slice::from_ref(&r)),
            RecordStatus::Valid(r)
        );
    }

    #[test]
    fn spf_exp_modifier_is_also_accepted() {
        let r = s("v=spf1 -all exp=explain.example.com");
        assert_eq!(
            validate_spf(std::slice::from_ref(&r)),
            RecordStatus::Valid(r)
        );
    }

    #[test]
    fn spf_still_rejects_a_genuinely_unknown_mechanism_shape() {
        // Not a modifier (no top-level `=`) and not a known mechanism name.
        match validate_spf(&[s("v=spf1 bogus ~all")]) {
            RecordStatus::Invalid(_) => {}
            other => panic!("expected Invalid, got {other:?}"),
        }
    }

    #[test]
    fn two_spf_records_is_invalid_per_rfc7208() {
        assert!(matches!(
            validate_spf(&[s("v=spf1 ~all"), s("v=spf1 -all")]),
            RecordStatus::Invalid(_)
        ));
    }

    #[test]
    fn spf_ignores_unrelated_txt_records_at_the_same_name() {
        let r = s("v=spf1 -all");
        let other = s("google-site-verification=abc123");
        assert_eq!(validate_spf(&[other, r.clone()]), RecordStatus::Valid(r));
    }

    #[test]
    fn missing_dmarc_when_no_v_dmarc1_record() {
        assert_eq!(validate_dmarc(&[]), RecordStatus::Missing);
    }

    #[test]
    fn valid_dmarc_record_with_reject_policy() {
        let r = s("v=DMARC1; p=reject; rua=mailto:d@example.com");
        assert_eq!(
            validate_dmarc(std::slice::from_ref(&r)),
            RecordStatus::Valid(r)
        );
    }

    #[test]
    fn dmarc_missing_policy_tag_is_invalid() {
        assert!(matches!(
            validate_dmarc(&[s("v=DMARC1; rua=mailto:d@example.com")]),
            RecordStatus::Invalid(_)
        ));
    }

    #[test]
    fn dmarc_with_bogus_policy_value_is_invalid() {
        assert!(matches!(
            validate_dmarc(&[s("v=DMARC1; p=maybe")]),
            RecordStatus::Invalid(_)
        ));
    }

    #[test]
    fn dkim_missing_when_no_p_tag_present() {
        assert_eq!(
            validate_dkim(&[s("some unrelated txt")]),
            RecordStatus::Missing
        );
    }

    #[test]
    fn valid_dkim_record_with_explicit_version() {
        let r = s("v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC");
        assert_eq!(
            validate_dkim(std::slice::from_ref(&r)),
            RecordStatus::Valid(r)
        );
    }

    #[test]
    fn valid_dkim_record_with_implied_default_version() {
        let r = s("k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC");
        assert_eq!(
            validate_dkim(std::slice::from_ref(&r)),
            RecordStatus::Valid(r)
        );
    }

    #[test]
    fn dkim_with_empty_p_tag_means_revoked_key() {
        assert!(matches!(
            validate_dkim(&[s("v=DKIM1; p=")]),
            RecordStatus::Invalid(_)
        ));
    }

    #[test]
    fn tag_value_handles_spacing_around_semicolons_and_equals() {
        assert_eq!(
            tag_value("v=DMARC1;  p = reject ", "p").as_deref(),
            Some("reject")
        );
    }
}
