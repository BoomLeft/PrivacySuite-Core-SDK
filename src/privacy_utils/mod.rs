//! Privacy utilities for URL sanitization and tracking prevention.
//!
//! Unified URL hygiene across all BoomLeft applications. Blocklist is
//! compiled-in (not fetched remotely) so sanitisation works offline and
//! cannot be disabled by network attackers.
//!
//! # API surface
//!
//! - [`strip_tracking_params`] / [`TRACKING_PARAMS`] — conservative
//!   tracking-parameter stripper. Only parameters whose names are
//!   overwhelmingly used for tracking (UTM, vendor click IDs, analytics
//!   session IDs). Very low false-positive rate.
//! - [`strip_tracking_params_aggressive`] / [`TRACKING_PARAMS_AGGRESSIVE`]
//!   — opt-in strict list that also removes extremely generic names
//!   (`ref`, `source`, `ts`, `cid`, `rid`, `ct`, `random_id`,
//!   `pingback_id`).
//! - [`url::validate_url`] — SSRF/homograph/scheme/credentials validation
//!   that returns a [`url::ValidatedUrl`] opaque wrapper. Every SDK
//!   consumer that performs a network fetch on behalf of a caller
//!   should run the input through this first.
//!
//! Both tracking-stripper variants strip parameters from the `?` query
//! AND, per defense-in-depth, from `#...` fragments that themselves
//! contain `key=value` pairs (common pattern in SPAs). Matrix parameters
//! (`/foo;utm_source=x/bar`) are deliberately not processed — the `url`
//! crate does not expose them, and hand-rolling a splitter risks
//! breaking legitimate pathsegments.

pub mod url;

use ::url::Url;

/// Conservative tracking-parameter blocklist.
///
/// Only parameters with an overwhelming tracking pedigree are included.
/// Entries like `ref`, `source`, `ts`, and `cid` (which frequently carry
/// legitimate application meaning) live in
/// [`TRACKING_PARAMS_AGGRESSIVE`] instead.
///
/// This blocklist is maintained and updated per release. Apps update their tracking
/// prevention by updating the SDK dependency, not by fetching configuration remotely.
pub const TRACKING_PARAMS: &[&str] = &[
    // ── Google Analytics / Ads ──────────────────────────────────────
    "utm_source",
    "utm_medium",
    "utm_campaign",
    "utm_term",
    "utm_content",
    "utm_id",
    "utm_referrer",
    "gclid",
    "gclsrc",
    "_ga",
    "_gl",
    "_gid",

    // ── Facebook / Meta ──────────────────────────────────────────────
    "fbclid",
    "fb_action_ids",
    "fb_action_types",
    "fb_source",
    "fb_ref",

    // ── Microsoft / Bing ────────────────────────────────────────────
    "msclkid",
    "msfpc",

    // ── TikTok ──────────────────────────────────────────────────────
    "ttclid",

    // ── Twitter / X ─────────────────────────────────────────────────
    "twclid",

    // ── Instagram ───────────────────────────────────────────────────
    "igshid",

    // ── LinkedIn ────────────────────────────────────────────────────
    "li_fat_id",

    // ── Adobe / Marketo ────────────────────────────────────────────
    "s_kwcid",
    "mkt_tok",
    "s_cid",

    // ── Pinterest ───────────────────────────────────────────────────
    "epik",

    // ── Mailchimp ───────────────────────────────────────────────────
    "mc_cid",
    "mc_eid",

    // ── HubSpot ─────────────────────────────────────────────────────
    "__hstc",
    "__hssc",
    "__hsfp",
    "_hsenc",
    "_hsmi",
    "hsCtaTracking",

    // ── Yandex ─────────────────────────────────────────────────────
    "yclid",
    "ymclid",

    // ── Drip ────────────────────────────────────────────────────────
    "__s",

    // ── Vero ────────────────────────────────────────────────────────
    "vero_id",
    "vero_conv",

    // ── Generic / Multi-platform (high-confidence only) ───────────
    "_ke",
    "trk",
    "trkCampaign",
    "trkInfo",
    "clickid",
    "click_id",

    // ── Podcast-specific ───────────────────────────────────────────
    "ck_subscriber_id",
];

/// Aggressive tracking-parameter blocklist — opt-in via
/// [`strip_tracking_params_aggressive`].
///
/// Contains [`TRACKING_PARAMS`] plus several extremely generic names that
/// are tracking on *some* hosts (notably GIF providers and link
/// shorteners) but are also used for legitimate application traffic
/// elsewhere:
///
/// - `ref` — git refs on GitHub, Bandcamp album refs, SPA routers.
/// - `source` — installers, doc-source tagging, some public REST APIs.
/// - `ts` — HMAC-signed URLs often include timestamp as part of the
///   signed payload. Stripping it invalidates the signature.
/// - `cid` / `rid` / `ct` — Google Meet meeting IDs, framework IDs, many
///   legitimate app-level identifiers.
/// - `random_id`, `pingback_id` — Giphy/Klipy tracking but also
///   random application routing tokens.
///
/// Use the aggressive variant when the caller's domain is known not to
/// rely on any of these parameters.
pub const TRACKING_PARAMS_AGGRESSIVE: &[&str] = &[
    // ── Generic / multi-platform (high-false-positive names) ─────
    "ref",
    "source",

    // ── GIF provider tracking (Giphy, Klipy) ──────────────────────
    "cid",
    "rid",
    "ct",
    "ts",
    "random_id",
    "pingback_id",
];

/// Strip known tracking parameters from a URL's query **and fragment**.
///
/// Parses the URL, removes all `?`-query parameters and any `#`-fragment
/// key/value pairs matching the conservative [`TRACKING_PARAMS`]
/// blocklist, then reconstructs the URL with proper percent-encoding.
///
/// The fragment handling is load-bearing because many tracking-aware
/// sites relocate trackers out of the `?`-query and into the hash
/// (e.g. `#utm_source=x&fbclid=y`) specifically to bypass naive
/// strippers. This function handles:
///
/// - Fragments that are a bare `key=value&key2=value2` list
///   (e.g. `#utm_source=twitter`).
/// - SPA-style fragments with their own query portion
///   (e.g. `#/route?utm_source=twitter`). The query portion of the
///   fragment is stripped; the rest is preserved byte-for-byte.
/// - Hashbang fragments (`#!/page?utm_source=x`).
///
/// Matrix parameters (`;key=value` inside a path segment) are **not**
/// processed — the `url` crate does not expose them and rolling a
/// custom splitter risks breaking pathsegments that legitimately
/// contain semicolons. Callers that need matrix-param stripping should
/// pre-process the URL.
///
/// # Errors
///
/// Returns `Err(...)` when `url_str` is not a well-formed URL.
///
/// # Example
///
/// ```ignore
/// let url = "https://example.com/?utm_source=twitter&id=123";
/// let clean = strip_tracking_params(url).unwrap();
/// assert_eq!(clean, "https://example.com/?id=123");
/// ```
pub fn strip_tracking_params(url_str: &str) -> Result<String, String> {
    strip_with_blocklist(url_str, TRACKING_PARAMS)
}

/// Aggressive variant of [`strip_tracking_params`] that additionally
/// removes the generic names in [`TRACKING_PARAMS_AGGRESSIVE`] (`ref`,
/// `source`, `ts`, `cid`, `rid`, `ct`, `random_id`, `pingback_id`).
///
/// These names are tracking on some domains but carry legitimate meaning
/// on others (git refs, HMAC-signed timestamps, SPA route IDs). Only
/// call this variant when the caller knows its domain won't break.
///
/// # Errors
///
/// Returns `Err(...)` when `url_str` is not a well-formed URL.
pub fn strip_tracking_params_aggressive(url_str: &str) -> Result<String, String> {
    // Concatenate the two lists without allocating (compile-time merge
    // isn't possible for `&[&str]`; a runtime filter-closure that checks
    // both slices is the cheapest).
    let mut parsed = Url::parse(url_str).map_err(|e| format!("Invalid URL: {e}"))?;

    let is_tracker = |key: &str| {
        TRACKING_PARAMS.iter().any(|p| key.eq_ignore_ascii_case(p))
            || TRACKING_PARAMS_AGGRESSIVE
                .iter()
                .any(|p| key.eq_ignore_ascii_case(p))
    };

    strip_query(&mut parsed, &is_tracker);
    strip_fragment(&mut parsed, &is_tracker);

    Ok(parsed.to_string())
}

/// Internal: run the conservative blocklist over both query and
/// fragment. Split out so the two public variants share a single code
/// path.
fn strip_with_blocklist(url_str: &str, blocklist: &[&str]) -> Result<String, String> {
    let mut parsed = Url::parse(url_str).map_err(|e| format!("Invalid URL: {e}"))?;

    // ASCII-case-insensitive compare avoids the per-iteration `to_lowercase`
    // allocation and sidesteps Unicode lowercase quirks (e.g., Turkish İ)
    // that could let a crafted key slip past the filter. Every entry in
    // the blocklist is pure ASCII.
    let is_tracker = |key: &str| blocklist.iter().any(|p| key.eq_ignore_ascii_case(p));

    strip_query(&mut parsed, &is_tracker);
    strip_fragment(&mut parsed, &is_tracker);

    Ok(parsed.to_string())
}

/// Strip tracker parameters from `?`-query in-place.
fn strip_query(parsed: &mut Url, is_tracker: &impl Fn(&str) -> bool) {
    let cleaned: Vec<(String, String)> = parsed
        .query_pairs()
        .filter(|(k, _)| !is_tracker(k))
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();

    if cleaned.is_empty() {
        parsed.set_query(None);
    } else {
        let new_query = ::url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs(cleaned.iter().map(|(k, v)| (k.as_str(), v.as_str())))
            .finish();
        parsed.set_query(Some(&new_query));
    }
}

/// Strip tracker parameters from the fragment in-place.
///
/// Handles three shapes:
/// 1. Bare `key=value&...` list (fragment contains `=` and no `?`).
/// 2. SPA-style `route?key=value&...` (fragment contains a `?`).
/// 3. Hashbang SPA-style `!/route?key=value&...` (same as case 2 once
///    we isolate the `?`).
///
/// If the fragment has no `=` or `?` at all, it's treated as an opaque
/// route identifier and left alone.
fn strip_fragment(parsed: &mut Url, is_tracker: &impl Fn(&str) -> bool) {
    let Some(fragment) = parsed.fragment() else {
        return;
    };
    if !fragment.contains('=') && !fragment.contains('?') {
        // Opaque route identifier — nothing to parse.
        return;
    }

    // Split into (prefix, query-portion). If there's an embedded `?`,
    // treat everything after it as the query section; otherwise the
    // whole fragment is one key=value list.
    let (prefix, query_part) = if let Some(idx) = fragment.find('?') {
        let (p, q) = fragment.split_at(idx);
        // q starts with '?'. Skip it.
        (p.to_owned(), q.get(1..).unwrap_or("").to_owned())
    } else {
        (String::new(), fragment.to_owned())
    };

    // Parse the fragment's query-portion the same way the `?`-query is
    // parsed: form-urlencoded key/value pairs.
    let kept: Vec<(String, String)> = ::url::form_urlencoded::parse(query_part.as_bytes())
        .filter(|(k, _)| !is_tracker(k))
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();

    // Reconstruct the fragment.
    let new_query = if kept.is_empty() {
        String::new()
    } else {
        ::url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs(kept.iter().map(|(k, v)| (k.as_str(), v.as_str())))
            .finish()
    };

    let new_fragment = match (prefix.is_empty(), new_query.is_empty()) {
        (true, true) => None,
        (true, false) => Some(new_query),
        (false, true) => Some(prefix),
        (false, false) => Some(format!("{prefix}?{new_query}")),
    };

    parsed.set_fragment(new_fragment.as_deref());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strip_utm_params() {
        let url = "https://example.com/?utm_source=twitter&utm_medium=social&id=123";
        let clean = strip_tracking_params(url).unwrap();
        assert_eq!(clean, "https://example.com/?id=123");
    }

    #[test]
    fn test_strip_fbclid() {
        let url = "https://example.com/?fbclid=abc123&page=1";
        let clean = strip_tracking_params(url).unwrap();
        assert_eq!(clean, "https://example.com/?page=1");
    }

    #[test]
    fn test_empty_query_after_strip() {
        let url = "https://example.com/?utm_source=google&utm_medium=cpc";
        let clean = strip_tracking_params(url).unwrap();
        assert_eq!(clean, "https://example.com/");
    }

    #[test]
    fn test_preserves_safe_params() {
        let url = "https://example.com/?id=123&name=test&utm_source=twitter";
        let clean = strip_tracking_params(url).unwrap();
        assert!(clean.contains("id=123"));
        assert!(clean.contains("name=test"));
        assert!(!clean.contains("utm_source"));
    }

    #[test]
    fn test_case_insensitive_matching() {
        let url = "https://example.com/?UTM_SOURCE=google&gCLiD=abc";
        let clean = strip_tracking_params(url).unwrap();
        assert!(!clean.contains("UTM_SOURCE"));
        assert!(!clean.contains("gCLiD"));
    }

    #[test]
    fn test_invalid_url() {
        let result = strip_tracking_params("not a url");
        assert!(result.is_err());
    }

    // --- Finding #3: fragments are stripped as well ---

    #[test]
    fn test_strip_utm_from_bare_fragment() {
        let url = "https://example.com/#utm_source=twitter&id=abc";
        let clean = strip_tracking_params(url).unwrap();
        assert!(!clean.contains("utm_source"));
        assert!(clean.contains("id=abc"));
    }

    #[test]
    fn test_strip_multiple_trackers_from_fragment() {
        let url = "https://example.com/page#utm_source=x&fbclid=y&gclid=z";
        let clean = strip_tracking_params(url).unwrap();
        assert!(!clean.contains("utm_source"));
        assert!(!clean.contains("fbclid"));
        assert!(!clean.contains("gclid"));
    }

    #[test]
    fn test_strip_utm_from_spa_style_fragment() {
        let url = "https://example.com/#/route?utm_source=twitter&keep=me";
        let clean = strip_tracking_params(url).unwrap();
        assert!(!clean.contains("utm_source"));
        // The route portion and the legitimate `keep` param must be preserved.
        assert!(clean.contains("keep=me"));
        assert!(clean.contains("/route"));
    }

    #[test]
    fn test_strip_utm_from_hashbang_fragment() {
        let url = "https://example.com/#!/page?utm_source=x&page=home";
        let clean = strip_tracking_params(url).unwrap();
        assert!(!clean.contains("utm_source"));
        assert!(clean.contains("page=home"));
        assert!(clean.contains("!/page"));
    }

    #[test]
    fn test_opaque_fragment_is_preserved() {
        // No `=` and no `?` ⇒ this is an anchor/route identifier, not a
        // key/value list. Must round-trip unchanged.
        let url = "https://example.com/page#section-3";
        let clean = strip_tracking_params(url).unwrap();
        assert!(clean.ends_with("#section-3"));
    }

    #[test]
    fn test_strip_removes_fragment_entirely_when_only_trackers() {
        let url = "https://example.com/#utm_source=x&gclid=y";
        let clean = strip_tracking_params(url).unwrap();
        // When the fragment held only trackers it should disappear
        // (no trailing `#`).
        assert!(!clean.contains('#'));
    }

    #[test]
    fn test_strip_fragment_and_query_together() {
        let url = "https://example.com/?utm_source=q&id=1#utm_source=f&section=a";
        let clean = strip_tracking_params(url).unwrap();
        assert!(!clean.contains("utm_source"));
        assert!(clean.contains("id=1"));
        assert!(clean.contains("section=a"));
    }

    // --- Finding #4: conservative default vs opt-in aggressive variant ---

    #[test]
    fn test_default_keeps_generic_ref_param() {
        // `ref=main` is legitimate on GitHub and many other sites; the
        // conservative blocklist must not strip it.
        let url = "https://github.com/x/y/blob/main/README.md?ref=main";
        let clean = strip_tracking_params(url).unwrap();
        assert!(clean.contains("ref=main"));
    }

    #[test]
    fn test_default_keeps_generic_source_param() {
        let url = "https://example.com/download?source=docs";
        let clean = strip_tracking_params(url).unwrap();
        assert!(clean.contains("source=docs"));
    }

    #[test]
    fn test_default_keeps_hmac_ts_param() {
        let url = "https://example.com/signed?ts=1700000000&sig=abc123";
        let clean = strip_tracking_params(url).unwrap();
        assert!(clean.contains("ts=1700000000"));
        assert!(clean.contains("sig=abc123"));
    }

    #[test]
    fn test_aggressive_strips_ref() {
        let url = "https://example.com/?ref=affiliate&id=1";
        let clean = strip_tracking_params_aggressive(url).unwrap();
        assert!(!clean.contains("ref=affiliate"));
        assert!(clean.contains("id=1"));
    }

    #[test]
    fn test_aggressive_strips_ts_and_cid() {
        let url = "https://example.com/?ts=123&cid=abc&utm_source=x&id=1";
        let clean = strip_tracking_params_aggressive(url).unwrap();
        assert!(!clean.contains("ts="));
        assert!(!clean.contains("cid="));
        assert!(!clean.contains("utm_source"));
        assert!(clean.contains("id=1"));
    }

    #[test]
    fn test_aggressive_also_strips_fragment() {
        let url = "https://example.com/#ref=x&id=1";
        let clean = strip_tracking_params_aggressive(url).unwrap();
        assert!(!clean.contains("ref="));
        assert!(clean.contains("id=1"));
    }

    #[test]
    fn test_aggressive_is_superset_of_default() {
        let url = "https://example.com/?utm_source=x&gclid=y&id=1";
        let a = strip_tracking_params(url).unwrap();
        let b = strip_tracking_params_aggressive(url).unwrap();
        // Both must strip the conservative trackers.
        assert!(!a.contains("utm_source"));
        assert!(!a.contains("gclid"));
        assert!(!b.contains("utm_source"));
        assert!(!b.contains("gclid"));
    }
}
