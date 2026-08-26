//! Black-box qualification acceptance tests for reproducible Lua 5.1 LNUM32 release candidate.
//!
//! Enforces candidate specification, deterministic archive packaging, external platform
//! attestations, multi-platform evidence index, fail-closed binary resolver, and non-promotion.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use luad_core::capabilities::{get_canonical_capabilities, SupportTier};
use luad_oracle::find_workspace_root;
use luad_oracle::gate_runner::GateSpec;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

type AttestationMutation = (&'static str, &'static str, Box<dyn Fn(&mut Value)>);
type IndexMutation = (
    &'static str,
    &'static str,
    Box<dyn Fn(&mut Value, &PathBuf)>,
);

fn sha256_digest(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

fn candidate_tool_bin() -> PathBuf {
    if let Ok(val) = std::env::var("LUAD_CANDIDATE_TOOL") {
        if !val.trim().is_empty() {
            return PathBuf::from(val);
        }
    }
    find_workspace_root().join("target/debug/luad-candidate")
}

fn run_tool(args: &[&str], envs: &[(&str, &str)]) -> std::io::Result<std::process::Output> {
    let mut cmd = Command::new(candidate_tool_bin());
    cmd.args(args).current_dir(find_workspace_root());
    for (k, v) in envs {
        cmd.env(k, v);
    }
    cmd.output()
}

struct TarEntry {
    name: String,
    mode: u32,
    uid: u32,
    gid: u32,
    mtime: u64,
    data: Vec<u8>,
}

fn parse_octal(bytes: &[u8]) -> u64 {
    let s = std::str::from_utf8(bytes)
        .unwrap_or("")
        .trim_matches(&['\0', ' '][..]);
    u64::from_str_radix(s, 8).unwrap_or(0)
}

fn parse_ustar(tar_bytes: &[u8]) -> Vec<TarEntry> {
    let mut entries = Vec::new();
    let mut offset = 0;
    while offset + 512 <= tar_bytes.len() {
        let block = &tar_bytes[offset..offset + 512];
        if block.iter().all(|&b| b == 0) {
            break;
        }
        let name = std::str::from_utf8(&block[0..100])
            .unwrap_or("")
            .trim_matches('\0')
            .to_string();
        let mode = parse_octal(&block[100..108]) as u32;
        let uid = parse_octal(&block[108..116]) as u32;
        let gid = parse_octal(&block[116..124]) as u32;
        let size = parse_octal(&block[124..136]) as usize;
        let mtime = parse_octal(&block[136..148]);

        offset += 512;
        let data = tar_bytes[offset..offset + size].to_vec();
        entries.push(TarEntry {
            name,
            mode,
            uid,
            gid,
            mtime,
            data,
        });
        let pad = (512 - (size % 512)) % 512;
        offset += size + pad;
    }
    entries
}

fn mock_prereq_res(
    gate: &str,
    spec: &str,
    res: &str,
    pass: usize,
    fail: usize,
    ign: usize,
    miss: &[&str],
) -> Value {
    json!({
        "gate_id": gate, "spec_hash": spec, "result_sha256": res,
        "exit_code": if fail == 0 && ign == 0 && miss.is_empty() { 0 } else { 1 },
        "success": fail == 0 && ign == 0 && miss.is_empty(),
        "passed_count": pass, "failed_count": fail, "ignored_count": ign,
        "missing_expected_tests": miss,
    })
}

#[test]
fn test_candidate_spec_and_provenance_schema() {
    let root = find_workspace_root();
    let spec_path = root.join("tests/candidates/lua51-lnum32-rc1.json");
    assert!(spec_path.exists(), "candidate spec file must exist");
    let spec_bytes = fs::read(&spec_path).expect("read candidate spec");
    let val: Value = serde_json::from_slice(&spec_bytes).expect("parse candidate spec JSON");

    assert_eq!(val["schema_version"], 1);
    assert_eq!(val["candidate_id"], "lua51-lnum32-0.1.0-rc1");
    assert_eq!(val["target"]["dialect"], "lua5.1");
    assert_eq!(val["target"]["patch_version"], "Lua 5.1.5");
    assert_eq!(val["target"]["profile"], "lua5.1-lnum32");
    assert_eq!(
        val["target"]["layout"],
        "int=4,sizet=4,inst=4,num=8,endian=1,integral_flag=4"
    );

    let majors = val["schema_majors"]
        .as_object()
        .expect("schema_majors object");
    assert_eq!(majors.len(), 17);
    for key in ["capabilities", "export", "manifest"] {
        assert_eq!(majors[key], 2, "Schema major for {key} must be 2");
    }
    for key in [
        "chunk", "disasm", "validate", "query", "xrefs", "cfg", "diff",
    ] {
        assert_eq!(majors[key], 1, "Schema major for {key} must be 1");
    }

    let platforms = val["required_platforms"]
        .as_array()
        .expect("required_platforms array");
    assert_eq!(platforms.len(), 2);
    let plat_ids: Vec<&str> = platforms
        .iter()
        .filter_map(|p| p["platform_id"].as_str())
        .collect();
    assert_eq!(plat_ids, vec!["linux-x86_64", "macos-aarch64"]);

    let prereqs = val["required_prerequisites"]
        .as_array()
        .expect("required_prerequisites array");
    assert_eq!(prereqs.len(), 4);
    for prereq in prereqs {
        let gate_id = prereq["gate_id"].as_str().unwrap();
        assert_ne!(
            gate_id, "gate-candidate-lua51-lnum32",
            "Candidate gate cannot be in prerequisites"
        );
        let ppath = root.join(prereq["spec_path"].as_str().unwrap());
        assert!(
            ppath.exists(),
            "prerequisite spec path must exist: {:?}",
            ppath
        );
        let pbytes = fs::read(&ppath).expect("read prereq spec");
        assert_eq!(
            sha256_digest(&pbytes),
            prereq["file_sha256"].as_str().unwrap()
        );
    }

    let fixtures = val["required_fixtures"]
        .as_array()
        .expect("required_fixtures array");
    assert_eq!(fixtures.len(), 3);
    for fixture in fixtures {
        let fpath = root.join(fixture["path"].as_str().unwrap());
        assert!(fpath.exists(), "fixture path must exist: {:?}", fpath);
        let fbytes = fs::read(&fpath).expect("read fixture file");
        assert_eq!(sha256_digest(&fbytes), fixture["sha256"].as_str().unwrap());
    }

    assert_eq!(val["archive_policy"]["format"], "tar.gz");
    assert_eq!(val["archive_policy"]["member_order"], "lexicographic");
    assert_eq!(val["archive_policy"]["mtime"], 0);
    assert_eq!(val["archive_policy"]["uid"], 0);
    assert_eq!(val["archive_policy"]["gid"], 0);
    assert_eq!(val["archive_policy"]["file_mode"], 420);
    assert_eq!(val["archive_policy"]["executable_mode"], 493);
    assert_eq!(val["archive_policy"]["extended_attributes"], false);
}

#[test]
fn test_candidate_tool_pack_deterministic_archive_and_ledger() {
    let root = find_workspace_root();
    let spec_path = root.join("tests/candidates/lua51-lnum32-rc1.json");
    let spec_bytes = fs::read(&spec_path).expect("read spec");
    let tmp_dir = tempfile::tempdir().expect("tempdir");

    let mock_bin = tmp_dir.path().join("mock_luad");
    let mock_bin_bytes = b"#!/bin/sh\necho luad\n";
    fs::write(&mock_bin, mock_bin_bytes).unwrap();
    let license_path = root.join("LICENSE");
    let license_bytes = fs::read(&license_path).expect("read license");
    let version_path = tmp_dir.path().join("VERSION.json");
    let version_bytes = b"{\"version\":\"0.1.0\"}\n";
    fs::write(&version_path, version_bytes).unwrap();

    let out_archive1 = tmp_dir.path().join("candidate1.tar.gz");
    let out_ledger1 = tmp_dir.path().join("ledger1.json");
    let out_archive2 = tmp_dir.path().join("candidate2.tar.gz");
    let out_ledger2 = tmp_dir.path().join("ledger2.json");

    let pack = |arc: &Path, led: &Path| {
        run_tool(
            &[
                "pack",
                "--spec",
                spec_path.to_str().unwrap(),
                "--binary",
                mock_bin.to_str().unwrap(),
                "--license",
                license_path.to_str().unwrap(),
                "--version-info",
                version_path.to_str().unwrap(),
                "--out-archive",
                arc.to_str().unwrap(),
                "--out-ledger",
                led.to_str().unwrap(),
            ],
            &[],
        )
        .expect("pack run")
    };

    assert!(
        pack(&out_archive1, &out_ledger1).status.success(),
        "pack run 1 must succeed"
    );
    assert!(
        pack(&out_archive2, &out_ledger2).status.success(),
        "pack run 2 must succeed"
    );

    let archive_bytes1 = fs::read(&out_archive1).unwrap();
    let archive_bytes2 = fs::read(&out_archive2).unwrap();
    assert_eq!(
        archive_bytes1, archive_bytes2,
        "Pack output must be byte-deterministic"
    );
    assert_eq!(
        fs::read(&out_ledger1).unwrap(),
        fs::read(&out_ledger2).unwrap()
    );

    assert_eq!(
        &archive_bytes1[0..3],
        &[0x1f, 0x8b, 0x08],
        "Gzip magic mismatch"
    );
    assert_eq!(
        u32::from_le_bytes(archive_bytes1[4..8].try_into().unwrap()),
        0,
        "Gzip mtime must be 0"
    );

    let decomp = Command::new("gzip")
        .args(["-dc", out_archive1.to_str().unwrap()])
        .output()
        .expect("gzip")
        .stdout;
    let entries = parse_ustar(&decomp);
    assert_eq!(entries.len(), 4, "Archive must contain exactly 4 members");

    let expected = [
        ("CANDIDATE.json", 420, spec_bytes.as_slice()),
        ("LICENSE", 420, license_bytes.as_slice()),
        ("VERSION.json", 420, version_bytes.as_slice()),
        ("bin/luad", 493, mock_bin_bytes.as_slice()),
    ];

    let ledger: Value = serde_json::from_slice(&fs::read(&out_ledger1).unwrap()).unwrap();
    let ledger_members = ledger["members"].as_array().expect("ledger members");
    assert_eq!(ledger_members.len(), 4);

    for (i, (exp_name, exp_mode, exp_data)) in expected.iter().enumerate() {
        let entry = &entries[i];
        assert_eq!(&entry.name, exp_name);
        assert_eq!(entry.mode, *exp_mode);
        assert_eq!((entry.uid, entry.gid, entry.mtime), (0, 0, 0));
        assert_eq!(&entry.data, exp_data);

        let lm = &ledger_members[i];
        assert_eq!(lm["path"], *exp_name);
        assert_eq!(lm["mode"], *exp_mode);
        assert_eq!(lm["uid"], 0);
        assert_eq!(lm["gid"], 0);
        assert_eq!(lm["mtime"], 0);
        assert_eq!(lm["size"], exp_data.len());
        assert_eq!(lm["sha256"], sha256_digest(exp_data));
    }
}

#[test]
fn test_candidate_tool_verify_platform_attestation_table_driven() {
    let root = find_workspace_root();
    let spec_path = root.join("tests/candidates/lua51-lnum32-rc1.json");
    let spec_bytes = fs::read(&spec_path).expect("read candidate spec");
    let spec_hash = sha256_digest(&spec_bytes);

    let tmp_dir = tempfile::tempdir().expect("tempdir");
    let mock_bin = tmp_dir.path().join("mock_luad");
    let mock_bin_bytes = b"#!/bin/sh\necho luad-bin\n";
    fs::write(&mock_bin, mock_bin_bytes).unwrap();
    let license_path = root.join("LICENSE");
    let version_path = tmp_dir.path().join("VERSION.json");
    fs::write(&version_path, b"{\"version\":\"0.1.0\"}\n").unwrap();

    let archive_path = tmp_dir.path().join("candidate.tar.gz");
    let ledger_path = tmp_dir.path().join("ledger.json");

    let pack_out = run_tool(
        &[
            "pack",
            "--spec",
            spec_path.to_str().unwrap(),
            "--binary",
            mock_bin.to_str().unwrap(),
            "--license",
            license_path.to_str().unwrap(),
            "--version-info",
            version_path.to_str().unwrap(),
            "--out-archive",
            archive_path.to_str().unwrap(),
            "--out-ledger",
            ledger_path.to_str().unwrap(),
        ],
        &[],
    )
    .expect("pack archive");
    assert!(
        pack_out.status.success(),
        "pack must succeed to establish valid test base"
    );

    let archive_bytes = fs::read(&archive_path).expect("read packed archive");
    let actual_archive_sha = sha256_digest(&archive_bytes);
    let actual_binary_sha = sha256_digest(mock_bin_bytes);
    let actual_ledger: Value = serde_json::from_slice(&fs::read(&ledger_path).unwrap()).unwrap();

    let base = json!({
        "schema_version": 1, "candidate_id": "lua51-lnum32-0.1.0-rc1", "spec_hash": spec_hash,
        "git_commit": "1111111111111111111111111111111111111111", "dirty": false,
        "platform": "macos-aarch64", "os": "macos", "arch": "aarch64",
        "target_triple": "aarch64-apple-darwin", "toolchain": "rustc 1.97.1",
        "build_host": "github-actions:macos-latest",
        "archive_sha256": actual_archive_sha, "binary_sha256": actual_binary_sha,
        "member_ledger": actual_ledger["members"],
        "target": {
            "dialect": "lua5.1", "patch_version": "Lua 5.1.5",
            "profile": "lua5.1-lnum32", "layout": "int=4,sizet=4,inst=4,num=8,endian=1,integral_flag=4"
        },
        "prerequisite_results": [
            mock_prereq_res("gate-authority-lua51-openwrt-lnum32", "085612ef3c9d702ce6bab8a245156803896c37c924a3cb693c54cc54eb29e3a9", "1000000000000000000000000000000000000000000000000000000000000001", 5, 0, 0, &[]),
            mock_prereq_res("gate-machine-contract", "07879b1833a07ec714ba353dd6780ebdf34f4ed6f02c3c32f5ac52e1a0413e05", "1000000000000000000000000000000000000000000000000000000000000002", 21, 0, 0, &[]),
            mock_prereq_res("gate-public-disasm-lua51", "5cbf5a737622966254c1218ae08ff3d4536131000350694cbca9bf2e9eed70d8", "1000000000000000000000000000000000000000000000000000000000000003", 12, 0, 0, &[]),
            mock_prereq_res("gate-retrieval-contract-lua51", "b053a74ebde9f866a16d59687f9c5e20583706b4c79e1ec989999754a9d8663a", "1000000000000000000000000000000000000000000000000000000000000004", 9, 0, 0, &[])
        ],
        "aggregate_check_success": true
    });

    let base_att_path = tmp_dir.path().join("base_attestation.json");
    fs::write(&base_att_path, serde_json::to_vec_pretty(&base).unwrap()).unwrap();

    let clean_verify = run_tool(
        &[
            "verify-platform",
            "--spec",
            spec_path.to_str().unwrap(),
            "--attestation",
            base_att_path.to_str().unwrap(),
            "--archive",
            archive_path.to_str().unwrap(),
        ],
        &[],
    )
    .expect("verify clean platform attestation");
    assert!(
        clean_verify.status.success(),
        "Clean platform attestation must pass verify-platform"
    );

    let mutations: Vec<AttestationMutation> = vec![
        (
            "dirty source commit",
            "dirty",
            Box::new(|v| v["dirty"] = json!(true)),
        ),
        (
            "empty git commit",
            "commit",
            Box::new(|v| v["git_commit"] = json!("")),
        ),
        (
            "mismatched spec hash",
            "spec_hash",
            Box::new(|v| {
                v["spec_hash"] =
                    json!("0000000000000000000000000000000000000000000000000000000000000000")
            }),
        ),
        (
            "unsupported platform",
            "platform",
            Box::new(|v| v["platform"] = json!("windows-x86_64")),
        ),
        (
            "target triple mismatch",
            "target_triple",
            Box::new(|v| v["target_triple"] = json!("x86_64-unknown-linux-gnu")),
        ),
        (
            "operating system mismatch",
            "os",
            Box::new(|v| v["os"] = json!("linux")),
        ),
        (
            "architecture mismatch",
            "arch",
            Box::new(|v| v["arch"] = json!("x86_64")),
        ),
        (
            "missing build host identity",
            "build_host",
            Box::new(|v| v["build_host"] = json!("")),
        ),
        (
            "tampered archive sha256",
            "archive",
            Box::new(|v| {
                v["archive_sha256"] =
                    json!("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
            }),
        ),
        (
            "tampered binary sha256",
            "binary",
            Box::new(|v| {
                v["binary_sha256"] =
                    json!("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
            }),
        ),
        (
            "aggregate check failed",
            "aggregate",
            Box::new(|v| v["aggregate_check_success"] = json!(false)),
        ),
        (
            "missing prerequisite gate",
            "prerequisite",
            Box::new(|v| {
                v["prerequisite_results"].as_array_mut().unwrap().pop();
            }),
        ),
        (
            "prerequisite spec hash mismatch",
            "spec_hash",
            Box::new(|v| {
                v["prerequisite_results"][0]["spec_hash"] =
                    json!("0000000000000000000000000000000000000000000000000000000000000000");
            }),
        ),
        (
            "prerequisite result hash mismatch",
            "result_sha256",
            Box::new(|v| {
                v["prerequisite_results"][0]["result_sha256"] =
                    json!("0000000000000000000000000000000000000000000000000000000000000000");
            }),
        ),
        (
            "failed prerequisite count",
            "failed",
            Box::new(|v| {
                v["prerequisite_results"][0]["failed_count"] = json!(1);
                v["prerequisite_results"][0]["success"] = json!(false);
            }),
        ),
        (
            "skipped prerequisite test",
            "ignored",
            Box::new(|v| {
                v["prerequisite_results"][0]["ignored_count"] = json!(1);
                v["prerequisite_results"][0]["success"] = json!(false);
            }),
        ),
        (
            "missing expected tests in prereq",
            "missing_expected_tests",
            Box::new(|v| {
                v["prerequisite_results"][0]["missing_expected_tests"] = json!(["test_missing"]);
                v["prerequisite_results"][0]["success"] = json!(false);
            }),
        ),
        (
            "self inclusion of candidate gate",
            "candidate",
            Box::new(|v| {
                v["prerequisite_results"]
                    .as_array_mut()
                    .unwrap()
                    .push(mock_prereq_res(
                        "gate-candidate-lua51-lnum32",
                        "085612ef3c9d702ce6bab8a245156803896c37c924a3cb693c54cc54eb29e3a9",
                        "1000000000000000000000000000000000000000000000000000000000000005",
                        7,
                        0,
                        0,
                        &[],
                    ));
            }),
        ),
        (
            "tampered member spec hash",
            "ledger",
            Box::new(|v| {
                v["member_ledger"][0]["sha256"] =
                    json!("0000000000000000000000000000000000000000000000000000000000000000");
            }),
        ),
        (
            "missing member in ledger",
            "member",
            Box::new(|v| {
                v["member_ledger"].as_array_mut().unwrap().pop();
            }),
        ),
        (
            "out of order member ledger",
            "order",
            Box::new(|v| {
                v["member_ledger"].as_array_mut().unwrap().swap(0, 1);
            }),
        ),
        (
            "wrong member permission mode",
            "mode",
            Box::new(|v| {
                v["member_ledger"][3]["mode"] = json!(420);
            }),
        ),
        (
            "target profile mismatch",
            "profile",
            Box::new(|v| {
                v["target"]["profile"] = json!("lua5.1-stock32");
            }),
        ),
        (
            "target layout mismatch",
            "layout",
            Box::new(|v| {
                v["target"]["layout"] =
                    json!("int=4,sizet=8,inst=4,num=8,endian=1,integral_flag=0");
            }),
        ),
    ];

    for (name, diag, mutate) in mutations {
        let mut att = base.clone();
        mutate(&mut att);
        let att_path = tmp_dir.path().join("attestation_mut.json");
        fs::write(&att_path, serde_json::to_vec_pretty(&att).unwrap()).unwrap();

        let out = run_tool(
            &[
                "verify-platform",
                "--spec",
                spec_path.to_str().unwrap(),
                "--attestation",
                att_path.to_str().unwrap(),
                "--archive",
                archive_path.to_str().unwrap(),
            ],
            &[],
        )
        .expect("verify-platform mutation");

        assert!(!out.status.success(), "Mutation '{name}' must be rejected");
        let stderr = String::from_utf8_lossy(&out.stderr).to_lowercase();
        assert!(
            stderr.contains(&diag.to_lowercase()),
            "Mutation '{name}' stderr must contain diagnostic '{diag}', got: {stderr}"
        );
    }
}

#[test]
fn test_candidate_tool_assemble_and_verify_index_table_driven() {
    let root = find_workspace_root();
    let spec_path = root.join("tests/candidates/lua51-lnum32-rc1.json");
    let spec_bytes = fs::read(&spec_path).expect("read candidate spec");
    let spec_hash = sha256_digest(&spec_bytes);

    let tmp_dir = tempfile::tempdir().expect("tempdir");
    let artifact_root = tmp_dir.path().join("artifacts");
    fs::create_dir_all(&artifact_root).unwrap();

    let linux_archive = artifact_root.join("luad-linux-x86_64.tar.gz");
    let macos_archive = artifact_root.join("luad-macos-aarch64.tar.gz");
    fs::write(&linux_archive, b"archive-linux-bytes").unwrap();
    fs::write(&macos_archive, b"archive-macos-bytes").unwrap();

    let mk_att = |plat: &str, triple: &str, bin_sha: &str, arc_name: &str, arc_bytes: &[u8]| {
        json!({
            "schema_version": 1, "candidate_id": "lua51-lnum32-0.1.0-rc1", "spec_hash": spec_hash,
            "git_commit": "1111111111111111111111111111111111111111", "dirty": false,
            "platform": plat,
            "os": if plat == "linux-x86_64" { "linux" } else { "macos" },
            "arch": if plat == "linux-x86_64" { "x86_64" } else { "aarch64" },
            "target_triple": triple, "toolchain": "rustc 1.97.1",
            "build_host": if plat == "linux-x86_64" { "github-actions:ubuntu-latest" } else { "github-actions:macos-latest" },
            "archive_path": arc_name, "archive_sha256": sha256_digest(arc_bytes),
            "binary_sha256": bin_sha,
            "member_ledger": [{
                "path": "bin/luad", "mode": 493, "uid": 0, "gid": 0,
                "mtime": 0, "size": 1, "sha256": bin_sha
            }],
            "prerequisite_results": [], "aggregate_check_success": true
        })
    };

    let linux_att = mk_att(
        "linux-x86_64",
        "x86_64-unknown-linux-gnu",
        "1111111111111111111111111111111111111111111111111111111111111111",
        "luad-linux-x86_64.tar.gz",
        b"archive-linux-bytes",
    );
    let macos_att = mk_att(
        "macos-aarch64",
        "aarch64-apple-darwin",
        "2222222222222222222222222222222222222222222222222222222222222222",
        "luad-macos-aarch64.tar.gz",
        b"archive-macos-bytes",
    );

    let linux_att_path = artifact_root.join("attestation-linux-x86_64.json");
    let macos_att_path = artifact_root.join("attestation-macos-aarch64.json");
    fs::write(
        &linux_att_path,
        serde_json::to_vec_pretty(&linux_att).unwrap(),
    )
    .unwrap();
    fs::write(
        &macos_att_path,
        serde_json::to_vec_pretty(&macos_att).unwrap(),
    )
    .unwrap();

    let index_path = artifact_root.join("candidate-index.json");

    let assemble_out = run_tool(
        &[
            "assemble-index",
            "--spec",
            spec_path.to_str().unwrap(),
            "--artifact-root",
            artifact_root.to_str().unwrap(),
            "--attestation",
            linux_att_path.to_str().unwrap(),
            "--attestation",
            macos_att_path.to_str().unwrap(),
            "--out",
            index_path.to_str().unwrap(),
        ],
        &[],
    )
    .expect("assemble-index");
    assert!(
        assemble_out.status.success(),
        "Clean assemble-index must succeed"
    );

    let clean_verify = run_tool(
        &[
            "verify-index",
            "--spec",
            spec_path.to_str().unwrap(),
            "--artifact-root",
            artifact_root.to_str().unwrap(),
            "--index",
            index_path.to_str().unwrap(),
        ],
        &[],
    )
    .expect("verify-index clean");
    assert!(
        clean_verify.status.success(),
        "Clean index must pass verify-index"
    );

    let base_index: Value = serde_json::from_slice(&fs::read(&index_path).unwrap()).unwrap();

    let mutations: Vec<IndexMutation> = vec![
        (
            "missing platform in index",
            "platform",
            Box::new(|v, _| {
                v["artifacts"].as_array_mut().unwrap().pop();
            }),
        ),
        (
            "duplicate platform in index",
            "duplicate",
            Box::new(|v, _| {
                let first = v["artifacts"][0].clone();
                v["artifacts"][1] = first;
            }),
        ),
        (
            "mismatched git commit across platforms",
            "commit",
            Box::new(|v, _| {
                v["artifacts"][1]["git_commit"] = json!("2222222222222222222222222222222222222222");
            }),
        ),
        (
            "mismatched spec hash across platforms",
            "spec_hash",
            Box::new(|v, _| {
                v["artifacts"][1]["spec_hash"] =
                    json!("0000000000000000000000000000000000000000000000000000000000000000");
            }),
        ),
        (
            "identical binary hash across distinct platforms",
            "binary_sha256",
            Box::new(|v, _| {
                let bin_sha = v["artifacts"][0]["binary_sha256"].clone();
                v["artifacts"][1]["binary_sha256"] = bin_sha;
            }),
        ),
        (
            "unknown extra platform",
            "platform",
            Box::new(|v, _| {
                let mut extra = v["artifacts"][0].clone();
                extra["platform"] = json!("freebsd-x86_64");
                v["artifacts"].as_array_mut().unwrap().push(extra);
            }),
        ),
        (
            "missing sidecar file",
            "attestation",
            Box::new(|_, root| {
                let _ = fs::remove_file(root.join("attestation-macos-aarch64.json"));
            }),
        ),
        (
            "tampered archive hash in index",
            "archive",
            Box::new(|v, _| {
                v["artifacts"][0]["archive_sha256"] =
                    json!("0000000000000000000000000000000000000000000000000000000000000000");
            }),
        ),
    ];

    for (name, diag, mutate) in mutations {
        let mut idx = base_index.clone();
        mutate(&mut idx, &artifact_root);
        let mut_index_path = artifact_root.join("mut-index.json");
        fs::write(&mut_index_path, serde_json::to_vec_pretty(&idx).unwrap()).unwrap();

        let verify_out = run_tool(
            &[
                "verify-index",
                "--spec",
                spec_path.to_str().unwrap(),
                "--artifact-root",
                artifact_root.to_str().unwrap(),
                "--index",
                mut_index_path.to_str().unwrap(),
            ],
            &[],
        )
        .expect("invoke verify-index");

        assert!(
            !verify_out.status.success(),
            "Index mutation '{name}' must be rejected"
        );
        let stderr = String::from_utf8_lossy(&verify_out.stderr).to_lowercase();
        assert!(
            stderr.contains(&diag.to_lowercase()),
            "Mutation '{name}' stderr must contain diagnostic '{diag}', got: {stderr}"
        );
    }
}

#[test]
fn test_candidate_binary_resolver_fail_closed_contract() {
    let root = find_workspace_root();
    let spec_path = root.join("tests/candidates/lua51-lnum32-rc1.json");
    let tmp_dir = tempfile::tempdir().expect("tempdir");
    let non_exec_file = tmp_dir.path().join("non_exec_binary");
    fs::write(&non_exec_file, b"not executable").expect("write non-executable");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&non_exec_file).unwrap().permissions();
        perms.set_mode(0o644);
        fs::set_permissions(&non_exec_file, perms).unwrap();
    }

    let bad_cases: Vec<(&str, &str, &str)> = vec![
        ("empty string", "", "empty"),
        (
            "missing path",
            "/tmp/nonexistent_luad_bin_candidate_override",
            "missing",
        ),
        (
            "directory path",
            tmp_dir.path().to_str().unwrap(),
            "directory",
        ),
        (
            "non-executable file",
            non_exec_file.to_str().unwrap(),
            "executable",
        ),
    ];

    for (desc, bad_bin, diag) in bad_cases {
        let out = run_tool(
            &["resolve-bin", "--spec", spec_path.to_str().unwrap()],
            &[("LUAD_CANDIDATE_BIN", bad_bin)],
        )
        .expect("invoke candidate tool resolve-bin with bad override");

        assert!(
            !out.status.success(),
            "LUAD_CANDIDATE_BIN with {desc} must fail closed"
        );
        let stderr = String::from_utf8_lossy(&out.stderr).to_lowercase();
        assert!(
            stderr.contains("luad_candidate_bin"),
            "Stderr must identify LUAD_CANDIDATE_BIN, got: {stderr}"
        );
        assert!(
            stderr.contains(diag),
            "Stderr for {desc} must contain diagnostic '{diag}', got: {stderr}"
        );
    }

    let valid_exec = tmp_dir.path().join("valid_custom_luad");
    fs::write(
        &valid_exec,
        b"#!/bin/sh\necho '{\"version\":\"0.1.0-custom\"}'\n",
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&valid_exec).unwrap().permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&valid_exec, perms).unwrap();
    }

    let pos_out = run_tool(
        &["resolve-bin", "--spec", spec_path.to_str().unwrap()],
        &[("LUAD_CANDIDATE_BIN", valid_exec.to_str().unwrap())],
    )
    .expect("invoke candidate tool resolve-bin with valid override");

    assert!(
        pos_out.status.success(),
        "Valid executable override must succeed"
    );
    let doc: Value = serde_json::from_slice(&pos_out.stdout).expect("parse resolve-bin JSON");
    assert_eq!(doc["selected_binary_path"], valid_exec.to_str().unwrap());
    assert_eq!(doc["override_active"], true);
}

#[test]
fn test_packaged_binary_smoke_and_checked_transcript() {
    let root = find_workspace_root();
    let spec_path = root.join("tests/candidates/lua51-lnum32-rc1.json");
    let lnum_fixture =
        root.join("tests/fixtures/authority/lua51-openwrt-lnum32/authority_lnum32.luac");
    assert!(lnum_fixture.exists(), "LNUM32 authority fixture must exist");
    let fixture_bytes = fs::read(&lnum_fixture).expect("read fixture bytes");
    let expected_fixture_sha = sha256_digest(&fixture_bytes);

    let out = run_tool(
        &[
            "transcript",
            "--spec",
            spec_path.to_str().unwrap(),
            "--fixture",
            lnum_fixture.to_str().unwrap(),
        ],
        &[],
    )
    .expect("invoke candidate tool transcript");

    assert!(
        out.status.success(),
        "Checked transcript on redistributable fixture must succeed"
    );

    let doc: Value = serde_json::from_slice(&out.stdout).expect("transcript output JSON");
    assert!(!doc["selected_binary_sha256"]
        .as_str()
        .unwrap_or("")
        .is_empty());
    assert_eq!(doc["input_fixture_sha256"], expected_fixture_sha);
    assert_eq!(doc["profile"], "lua5.1-lnum32");
    assert_eq!(
        doc["layout"],
        "int=4,sizet=4,inst=4,num=8,endian=1,integral_flag=4"
    );

    for wf in ["inspect", "validate", "disasm", "query", "xrefs", "export"] {
        assert_eq!(
            doc["workflows"][wf]["status"], "ok",
            "Workflow {wf} status must be ok"
        );
        let evidence = &doc["workflows"][wf]["evidence"];
        assert!(
            !evidence.is_null(),
            "Workflow {wf} must carry non-empty evidence"
        );
    }
}

#[test]
fn test_candidate_gate_non_promotion_and_experimental_invariants() {
    let manifest = get_canonical_capabilities("0.1.0");
    assert!(
        manifest.supported_dialects.is_empty(),
        "supported_dialects must remain empty without promoted release evidence"
    );

    let lnum_dialect = manifest
        .dialects
        .iter()
        .find(|d| d.id == "lua5.1")
        .expect("lua5.1 dialect present");

    assert_eq!(
        lnum_dialect.status,
        SupportTier::Experimental,
        "lua5.1 dialect must remain Experimental during candidate sprint"
    );

    let root = find_workspace_root();
    let gate_spec_path = root.join("tests/gates/gate-candidate-lua51-lnum32.json");
    assert!(gate_spec_path.exists(), "gate spec file must exist");
    let content = fs::read_to_string(&gate_spec_path).expect("read gate spec");
    let spec: GateSpec = serde_json::from_str(&content).expect("parse gate spec");

    assert_eq!(spec.gate_id, "gate-candidate-lua51-lnum32");
    assert!(
        !spec.gate_id.starts_with("gate-release-"),
        "Candidate gate ID must not start with gate-release- to prevent release manifest promotion"
    );
}
