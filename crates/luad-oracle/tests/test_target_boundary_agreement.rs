//! Agreement between every document that states the version-1 target boundary.
//!
//! The frozen boundary table in `docs/RELEASING.md` is the authority. The same profile
//! identities and the same count appear in the roadmap's support boundary, the release
//! qualification order, and the product requirements. A target added to or removed from
//! one document without the others leaves a planner able to follow one document to a
//! conclusion the rest forbid.
//!
//! Exercises:
//! 1. The frozen boundary table names at least two profiles and its prose count word
//!    matches the number of table rows.
//! 2. Every profile identity in the table appears in the roadmap's support boundary,
//!    the release qualification order, and the product requirements' version-1 goals,
//!    1.0 release criterion, and decision summary; the two sections that enumerate the
//!    promoted set name it exactly, so an extra entry fails as well as a missing one.
//! 3. The product boundary states that LuaJIT and Luau are outside the product, and the
//!    specific wordings that previously scheduled them as future work stay retired.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

/// Profile identities are written as inline code spans of the form `lua5.N[-vendor]`.
fn profile_identities(text: &str) -> BTreeSet<String> {
    let mut found = BTreeSet::new();
    let bytes: Vec<char> = text.chars().collect();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == '`' {
            if let Some(end) = (i + 1..bytes.len()).find(|&j| bytes[j] == '`') {
                let span: String = bytes[i + 1..end].iter().collect();
                if span.starts_with("lua5.")
                    && span.len() > 5
                    && span
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
                {
                    found.insert(span);
                }
                i = end + 1;
                continue;
            }
        }
        i += 1;
    }
    found
}

/// The section of `text` starting at `heading` and ending at the next heading of the
/// same or higher level.
fn section<'a>(text: &'a str, heading: &str) -> &'a str {
    let start = text
        .find(heading)
        .unwrap_or_else(|| panic!("heading not found: {heading}"));
    let level = heading.chars().take_while(|&c| c == '#').count();
    let rest = &text[start + heading.len()..];
    let end = rest
        .match_indices('\n')
        .filter_map(|(idx, _)| {
            let line = rest[idx + 1..].lines().next()?;
            let found = line.chars().take_while(|&c| c == '#').count();
            (found > 0 && found <= level).then_some(idx + 1)
        })
        .next()
        .unwrap_or(rest.len());
    &rest[..end]
}

fn read(root: &Path, relative: &str) -> String {
    fs::read_to_string(root.join(relative))
        .unwrap_or_else(|error| panic!("{relative} must be readable: {error}"))
}

#[test]
fn test_frozen_boundary_count_matches_its_table() {
    let root = luad_oracle::find_workspace_root();
    let releasing = read(&root, "docs/RELEASING.md");
    let boundary = section(&releasing, "## Frozen version-1 boundary");

    let rows = boundary
        .lines()
        .filter(|line| line.starts_with('|') && line.contains("`lua5."))
        .count();
    assert!(
        rows >= 2,
        "the frozen boundary table must name the promoted profiles, found {rows} rows"
    );

    let words = [
        ("one", 1),
        ("two", 2),
        ("three", 3),
        ("four", 4),
        ("five", 5),
        ("six", 6),
    ];
    let stated = words
        .iter()
        .find(|(word, _)| boundary.contains(&format!("exactly {word} independent target")))
        .map(|(_, count)| *count)
        .expect("the boundary must state 'exactly <count> independent target identities'");
    assert_eq!(
        stated, rows,
        "the frozen boundary states {stated} targets but its table has {rows} rows"
    );
}

#[test]
fn test_every_promoted_profile_appears_in_each_authoritative_document() {
    let root = luad_oracle::find_workspace_root();
    let releasing = read(&root, "docs/RELEASING.md");
    let roadmap = read(&root, "ROADMAP.md");
    let prd = read(&root, "PRD.md");

    let promoted = profile_identities(section(&releasing, "## Frozen version-1 boundary"));
    assert!(
        promoted.len() >= 2,
        "expected the frozen boundary to name profiles, found {promoted:?}"
    );

    // Each site is bounded to its own section so a profile named elsewhere in the
    // document cannot satisfy the check.
    let sites: [(&str, &str); 5] = [
        (
            "the roadmap's version-1 support boundary",
            section(&roadmap, "### Version 1 support boundary"),
        ),
        (
            "the release qualification order",
            section(&releasing, "## Release scope and order"),
        ),
        (
            "the product requirements' version-1 goals",
            section(&prd, "### 3.1 Version 1 goals"),
        ),
        (
            "the product requirements' 1.0 release criterion",
            section(&prd, "### 13.2 Version 1.0"),
        ),
        (
            "the product requirements' decision summary",
            section(&prd, "### 16.1 Decisions made by this PRD"),
        ),
    ];

    for (name, body) in &sites {
        let named = profile_identities(body);
        let missing: Vec<&String> = promoted.difference(&named).collect();
        assert!(
            missing.is_empty(),
            "{name} omits promoted profiles {missing:?}; it names {named:?}"
        );
    }

    // The roadmap's boundary and the release order are the two places that enumerate
    // the promoted set, so each must equal it exactly: an extra entry promotes a target
    // the frozen boundary does not.
    for (name, body) in [
        (
            "the roadmap's version-1 support boundary",
            section(&roadmap, "### Version 1 support boundary"),
        ),
        (
            "the release qualification order",
            section(&releasing, "## Release scope and order"),
        ),
    ] {
        let named = profile_identities(body);
        let extra: Vec<&String> = named.difference(&promoted).collect();
        assert!(
            extra.is_empty(),
            "{name} promotes {extra:?}, which the frozen release boundary omits"
        );
    }
}

#[test]
fn test_the_out_of_scope_boundary_is_stated_and_its_retired_wordings_stay_retired() {
    let root = luad_oracle::find_workspace_root();
    let prd = read(&root, "PRD.md");
    let roadmap = read(&root, "ROADMAP.md");

    // The product boundary must say so once, plainly.
    assert!(
        roadmap.contains("LuaJIT and Luau are separate bytecode systems outside the product"),
        "the roadmap must state the LuaJIT and Luau product boundary"
    );

    // These exact wordings scheduled LuaJIT or Luau as future work before the boundary
    // was set. This guards their return, not every possible way to schedule the work:
    // a newly worded stage would pass here and is caught by review, not by this test.
    let retired = [
        "LuaJIT 2.0/2.1 and significant maintained forks as separate dialect modules",
        "LuaJIT requires the separate product decision",
        "once those dialects are supported",
        "explicit post-release prioritization decision",
    ];
    for phrase in retired {
        for (name, body) in [("PRD.md", &prd), ("ROADMAP.md", &roadmap)] {
            assert!(
                !body.contains(phrase),
                "{name} restates a retired out-of-scope scheduling wording: {phrase:?}"
            );
        }
    }
}
