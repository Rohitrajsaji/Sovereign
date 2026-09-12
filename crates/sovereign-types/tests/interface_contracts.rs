use serde_json::Value;
use sovereign_types::interface_contracts::InterfaceContractManifest;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .unwrap_or_else(|| panic!("sovereign-types must live under <workspace>/crates"))
        .to_path_buf()
}

fn read_json(path: &Path) -> Value {
    let bytes = fs::read(path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
    serde_json::from_slice(&bytes)
        .unwrap_or_else(|error| panic!("parse {}: {error}", path.display()))
}

fn manifest() -> InterfaceContractManifest {
    let path = workspace_root().join("schemas/interface-contracts/v1.json");
    let bytes = fs::read(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
    serde_json::from_slice(&bytes)
        .unwrap_or_else(|error| panic!("parse typed manifest {}: {error}", path.display()))
}

#[test]
fn interface_contracts_manifest_matches_frozen_roadmap() {
    let root = workspace_root();
    let manifest_json = read_json(&root.join("schemas/interface-contracts/v1.json"));
    let roadmap_json = read_json(&root.join("output/implementation-plan.json"));
    assert_eq!(
        manifest_json.get("stable_interface_contracts"),
        roadmap_json.get("stable_interface_contracts"),
        "stable interface contracts must be copied verbatim from the frozen roadmap"
    );
}

#[test]
fn interface_contracts_have_exactly_one_owner_and_no_duplicate_authority() {
    let manifest = manifest();
    assert_eq!(manifest.contract_version.major, 1);
    assert_eq!(manifest.stable_interface_contracts.len(), 22);

    let mut interfaces = BTreeSet::new();
    for contract in &manifest.stable_interface_contracts {
        assert!(
            interfaces.insert(format!("{:?}", contract.interface)),
            "duplicate stable interface {:?}",
            contract.interface
        );
    }

    let controller_count = manifest
        .stable_interface_contracts
        .iter()
        .filter(|contract| format!("{:?}", contract.interface) == "Controller")
        .count();
    assert_eq!(
        controller_count, 1,
        "Controller authority must have one owner"
    );
}

#[test]
fn interface_contracts_task_references_resolve_in_roadmap() {
    let root = workspace_root();
    let roadmap = read_json(&root.join("output/implementation-plan.json"));
    let task_ids: BTreeSet<String> = roadmap
        .get("milestones")
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("roadmap milestones missing"))
        .iter()
        .flat_map(|milestone| {
            milestone
                .get("tasks")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
        })
        .filter_map(|task| task.get("task_id").and_then(Value::as_str))
        .map(str::to_owned)
        .collect();

    for contract in manifest().stable_interface_contracts {
        assert!(
            task_ids.contains(&contract.introduced_by),
            "unknown introduced_by task {}",
            contract.introduced_by
        );
        for task_id in contract.extended_by {
            assert!(
                task_ids.contains(&task_id),
                "unknown extended_by task {task_id}"
            );
        }
    }
}

#[test]
fn interface_contracts_forbidden_dependency_directions_are_absent() {
    let root = workspace_root();
    let manifest = manifest();
    let rules: BTreeMap<_, _> = manifest
        .forbidden_dependency_rules
        .into_iter()
        .map(|rule| (rule.subject, rule.must_not_depend_on))
        .collect();

    for (subject, forbidden) in rules {
        let cargo_path = root.join(&subject).join("Cargo.toml");
        if !cargo_path.exists() {
            continue;
        }
        let cargo = fs::read_to_string(&cargo_path)
            .unwrap_or_else(|error| panic!("read {}: {error}", cargo_path.display()));
        let dependencies = dependency_names(&cargo);
        for forbidden_path in forbidden {
            let package = forbidden_path
                .rsplit('/')
                .next()
                .unwrap_or(forbidden_path.as_str());
            assert!(
                !dependencies.contains(package),
                "forbidden dependency direction: {subject} -> {forbidden_path}"
            );
        }
    }
}

fn dependency_names(cargo_toml: &str) -> BTreeSet<&str> {
    let mut names = BTreeSet::new();
    let mut in_dependencies = false;
    for raw_line in cargo_toml.lines() {
        let line = raw_line.trim();
        if line.starts_with('[') {
            in_dependencies = line == "[dependencies]";
            continue;
        }
        if !in_dependencies || line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((name, _)) = line.split_once('=') {
            names.insert(name.trim());
        }
    }
    names
}
