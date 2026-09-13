use sovereign_repo::{
    DependencyGraph, ProjectRegistry, StructuralConfig, StructuralIndex, StructuralLookup,
    StructuralRetriever, SymbolIndex,
};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

struct TestRepo(PathBuf);
impl TestRepo {
    fn new(label: &str) -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let path = std::env::temp_dir().join(format!(
            "sovereign-structural-{label}-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir_all(path.join("src")).unwrap_or_else(|e| panic!("mkdir: {e}"));
        git(&path, &["init", "-q"]);
        fs::write(path.join("src/lib.rs"), "mod service;\npub fn root() {}\n")
            .unwrap_or_else(|e| panic!("write: {e}"));
        fs::write(
            path.join("src/service.rs"),
            "use crate::util::helper;\npub struct Service;\npub fn run() { helper(); }\n",
        )
        .unwrap_or_else(|e| panic!("write: {e}"));
        fs::write(path.join("src/util.rs"), "pub fn helper() {}\n")
            .unwrap_or_else(|e| panic!("write: {e}"));
        fs::write(
            path.join("src/view.ts"),
            "import { helper } from './helper';\nexport function render() { return helper(); }\n",
        )
        .unwrap_or_else(|e| panic!("write: {e}"));
        fs::write(path.join("src/widget.tsx"), "import { render } from './view';\nexport function Widget() { return <div>{render()}</div>; }\n").unwrap_or_else(|e| panic!("write: {e}"));
        fs::write(path.join("notes.py"), "def unsupported(): pass\n")
            .unwrap_or_else(|e| panic!("write: {e}"));
        git(&path, &["add", "."]);
        git(&path, &["commit", "-q", "-m", "fixture"]);
        Self(path)
    }
    fn path(&self) -> &Path {
        &self.0
    }
    fn db(&self) -> PathBuf {
        self.0.with_extension("structural.sqlite3")
    }
}
impl Drop for TestRepo {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
        let _ = fs::remove_file(self.db());
    }
}
fn git(root: &Path, args: &[&str]) {
    let status = Command::new("git")
        .current_dir(root)
        .args(args)
        .env("GIT_AUTHOR_NAME", "Fixture")
        .env("GIT_AUTHOR_EMAIL", "fixture@example.invalid")
        .env("GIT_COMMITTER_NAME", "Fixture")
        .env("GIT_COMMITTER_EMAIL", "fixture@example.invalid")
        .status()
        .unwrap_or_else(|e| panic!("git: {e}"));
    assert!(status.success());
}
fn registry(repo: &TestRepo) -> ProjectRegistry {
    let mut r = ProjectRegistry::new();
    r.register("repo.fixture", repo.path())
        .unwrap_or_else(|e| panic!("register: {e}"));
    r
}
fn index<'a>(r: &'a ProjectRegistry, repo: &TestRepo) -> StructuralIndex<'a> {
    StructuralIndex::open(r, "repo.fixture", repo.db(), StructuralConfig::default())
        .unwrap_or_else(|e| panic!("open: {e}"))
}

#[test]
fn structural_definition_lookup_covers_rust_typescript_and_tsx() {
    let repo = TestRepo::new("defs");
    let r = registry(&repo);
    let mut idx = index(&r, &repo);
    let report = idx.rebuild().unwrap_or_else(|e| panic!("rebuild: {e}"));
    println!(
        "M2_T02_STRUCTURAL_SNAPSHOT={}",
        serde_json::to_string(&report.snapshot).unwrap_or_else(|e| panic!("snapshot json: {e}"))
    );
    let service = idx
        .definitions("Service")
        .unwrap_or_else(|e| panic!("defs: {e}"));
    assert_eq!(service.len(), 1);
    assert_eq!(service[0].language, "rust");
    let render = idx
        .definitions("render")
        .unwrap_or_else(|e| panic!("defs: {e}"));
    assert_eq!(render.len(), 1);
    assert_eq!(render[0].language, "typescript");
    let widget = idx
        .definitions("Widget")
        .unwrap_or_else(|e| panic!("defs: {e}"));
    assert_eq!(widget.len(), 1);
    assert_eq!(widget[0].language, "tsx");
    assert!(service[0].source_digest.starts_with("sha256:"));
    assert!(service[0].parser_fingerprint.starts_with("sha256:"));
}

#[test]
fn structural_import_neighborhood_extracts_language_aware_relations() {
    let repo = TestRepo::new("edges");
    let r = registry(&repo);
    let mut idx = index(&r, &repo);
    idx.rebuild().unwrap_or_else(|e| panic!("rebuild: {e}"));
    let rust = idx
        .import_neighborhood(Path::new("src/service.rs"))
        .unwrap_or_else(|e| panic!("edges: {e}"));
    assert!(
        rust.iter()
            .any(|e| e.target.contains("crate::util::helper"))
    );
    let ts = idx
        .import_neighborhood(Path::new("src/view.ts"))
        .unwrap_or_else(|e| panic!("edges: {e}"));
    assert!(ts.iter().any(|e| e.target == "./helper"));
    let root = idx
        .import_neighborhood(Path::new("src/lib.rs"))
        .unwrap_or_else(|e| panic!("edges: {e}"));
    assert!(
        root.iter()
            .any(|e| e.relation == "module" && e.target == "service")
    );
}

#[test]
fn structural_changed_symbol_reindex_and_zero_hit_refresh_use_exact_source_truth() {
    let repo = TestRepo::new("change");
    let r = registry(&repo);
    let mut idx = index(&r, &repo);
    idx.rebuild().unwrap_or_else(|e| panic!("rebuild: {e}"));
    assert_eq!(
        idx.definitions("helper")
            .unwrap_or_else(|e| panic!("before: {e}"))
            .len(),
        1
    );
    fs::write(
        repo.path().join("src/util.rs"),
        "pub fn renamed_helper() {}\n",
    )
    .unwrap_or_else(|e| panic!("write: {e}"));
    assert!(
        idx.definitions("helper")
            .unwrap_or_else(|e| panic!("old: {e}"))
            .is_empty()
    );
    let fresh = idx
        .definitions("renamed_helper")
        .unwrap_or_else(|e| panic!("new: {e}"));
    assert_eq!(fresh.len(), 1);
}

#[test]
fn structural_ignored_change_is_detected_even_when_git_snapshot_is_unchanged() {
    let repo = TestRepo::new("ignored");
    fs::write(repo.path().join(".gitignore"), "ignored.ts\n")
        .unwrap_or_else(|e| panic!("ignore: {e}"));
    git(repo.path(), &["add", ".gitignore"]);
    git(repo.path(), &["commit", "-q", "-m", "ignore"]);
    let r = registry(&repo);
    let mut idx = index(&r, &repo);
    idx.rebuild().unwrap_or_else(|e| panic!("rebuild: {e}"));
    fs::write(
        repo.path().join("ignored.ts"),
        "export function invisibleFresh() {}\n",
    )
    .unwrap_or_else(|e| panic!("write: {e}"));
    let hit = idx
        .definitions("invisibleFresh")
        .unwrap_or_else(|e| panic!("lookup: {e}"));
    assert_eq!(hit.len(), 1);
    assert_eq!(hit[0].relative_path, PathBuf::from("ignored.ts"));
}

#[test]
fn structural_dependency_neighbor_refresh_is_limited_to_affected_importers_and_tests() {
    let repo = TestRepo::new("neighbors");
    fs::write(
        repo.path().join("src/service_test.rs"),
        "use crate::service::Service;\n#[test] fn smoke(){ let _=Service; }\n",
    )
    .unwrap_or_else(|e| panic!("test: {e}"));
    let r = registry(&repo);
    let mut idx = index(&r, &repo);
    idx.rebuild().unwrap_or_else(|e| panic!("rebuild: {e}"));
    fs::write(
        repo.path().join("src/service.rs"),
        "use crate::util::helper;\npub struct Service2;\npub fn run(){helper();}\n",
    )
    .unwrap_or_else(|e| panic!("write: {e}"));
    let report = idx.refresh().unwrap_or_else(|e| panic!("refresh: {e}"));
    assert!(
        report
            .reparsed_paths
            .contains(&PathBuf::from("src/service.rs"))
    );
    assert!(
        report
            .affected_neighbor_paths
            .contains(&PathBuf::from("src/lib.rs"))
            || report
                .affected_neighbor_paths
                .contains(&PathBuf::from("src/service_test.rs"))
    );
    assert!(
        !report
            .reparsed_paths
            .contains(&PathBuf::from("src/widget.tsx"))
    );
}

#[test]
fn structural_unsupported_language_gracefully_falls_back() {
    let repo = TestRepo::new("unsupported");
    let r = registry(&repo);
    let mut idx = index(&r, &repo);
    match idx
        .structural_for_path(Path::new("notes.py"))
        .unwrap_or_else(|e| panic!("lookup: {e}"))
    {
        StructuralLookup::UnsupportedLanguage { path } => {
            assert_eq!(path, PathBuf::from("notes.py"));
        }
        StructuralLookup::Indexed(_) => panic!("python unexpectedly indexed"),
    }
}

#[test]
fn structural_parser_batches_keep_only_one_ast_live_and_stay_bounded() {
    let repo = TestRepo::new("bounded");
    for i in 0..96 {
        fs::write(
            repo.path().join("src").join(format!("bulk_{i}.rs")),
            format!("pub fn bulk_{i}() {{}}\n"),
        )
        .unwrap_or_else(|e| panic!("write: {e}"));
    }
    let r = registry(&repo);
    let config = StructuralConfig {
        batch_files: 8,
        max_file_bytes: 1024 * 1024,
        ..StructuralConfig::default()
    };
    let mut idx = StructuralIndex::open(&r, "repo.fixture", repo.db(), config)
        .unwrap_or_else(|e| panic!("open: {e}"));
    let report = idx.rebuild().unwrap_or_else(|e| panic!("rebuild: {e}"));
    assert_eq!(report.telemetry.max_live_asts, 1);
    assert_eq!(report.telemetry.parser_batch_file_limit, 8);
    assert!(report.telemetry.peak_source_bytes <= 1024 * 1024);
    let peak_rss = report
        .telemetry
        .peak_process_rss_bytes
        .unwrap_or_else(|| panic!("missing process RSS sample"));
    assert!(
        peak_rss <= 512 * 1024 * 1024,
        "parser/index worker peak RSS exceeded frozen 512 MiB profile: {peak_rss}"
    );
    assert!(report.telemetry.parsed_files >= 100);
    println!(
        "M2_T02_STRUCTURAL_TELEMETRY={}",
        serde_json::to_string(&report.telemetry).unwrap_or_else(|e| panic!("telemetry json: {e}"))
    );
}

#[test]
fn structural_incompatible_schema_or_parser_fingerprint_discards_derived_state() {
    let repo = TestRepo::new("schema");
    let r = registry(&repo);
    {
        let mut idx = index(&r, &repo);
        idx.rebuild().unwrap_or_else(|e| panic!("rebuild: {e}"));
        assert!(
            !idx.definitions("Service")
                .unwrap_or_else(|e| panic!("defs: {e}"))
                .is_empty()
        );
    }
    let db = repo.db();
    let conn = rusqlite::Connection::open(&db).unwrap_or_else(|e| panic!("db: {e}"));
    conn.execute(
        "UPDATE structural_metadata SET value_int=999 WHERE key='schema_version'",
        [],
    )
    .unwrap_or_else(|e| panic!("tamper: {e}"));
    drop(conn);
    let mut reopened = index(&r, &repo);
    assert!(
        reopened
            .snapshot()
            .unwrap_or_else(|e| panic!("snapshot: {e}"))
            .is_none()
    );
    assert_eq!(
        reopened
            .definitions("Service")
            .unwrap_or_else(|e| panic!("rebuild query: {e}"))
            .len(),
        1
    );
    drop(reopened);

    let conn = rusqlite::Connection::open(&db).unwrap_or_else(|e| panic!("db parser: {e}"));
    conn.execute(
        "UPDATE structural_metadata SET value_text='sha256:incompatible' WHERE key='parser_fingerprint'",
        [],
    )
    .unwrap_or_else(|e| panic!("tamper parser fingerprint: {e}"));
    drop(conn);
    let mut reparsed = index(&r, &repo);
    assert!(
        reparsed
            .snapshot()
            .unwrap_or_else(|e| panic!("parser snapshot: {e}"))
            .is_none()
    );
    assert_eq!(
        reparsed
            .definitions("Service")
            .unwrap_or_else(|e| panic!("parser rebuild query: {e}"))
            .len(),
        1
    );
    drop(reparsed);

    let conn = rusqlite::Connection::open(&db).unwrap_or_else(|e| panic!("db schema: {e}"));
    conn.execute(
        "UPDATE structural_metadata SET value_text='sha256:incompatible-schema' WHERE key='schema_fingerprint'",
        [],
    )
    .unwrap_or_else(|e| panic!("tamper schema fingerprint: {e}"));
    drop(conn);
    let mut reschemed = index(&r, &repo);
    assert!(
        reschemed
            .snapshot()
            .unwrap_or_else(|e| panic!("schema fingerprint snapshot: {e}"))
            .is_none()
    );
    assert_eq!(
        reschemed
            .definitions("Service")
            .unwrap_or_else(|e| panic!("schema fingerprint rebuild query: {e}"))
            .len(),
        1
    );
}
