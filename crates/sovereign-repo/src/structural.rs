#![allow(clippy::missing_errors_doc, clippy::too_many_lines)]

use crate::{ProjectRegistry, RepoError, collect_regular_files, sha256_prefixed};
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use tree_sitter::{Language, Node, Parser};

const STRUCTURAL_SCHEMA_VERSION: i64 = 1;
const STRUCTURAL_SCHEMA_FINGERPRINT: &str =
    "sha256:2ef8f2108fc5eb706b79881294c476f2896b4ad4e601f192cb87ae9154239e84";
const PARSER_VERSION_MANIFEST: &str =
    "tree-sitter=0.25.10;rust=0.24.0;typescript=0.23.2;languages=rust,typescript,tsx";
const DEFAULT_MAX_FILES: usize = 50_000;
const DEFAULT_MAX_FILE_BYTES: u64 = 2 * 1024 * 1024;
const DEFAULT_BATCH_FILES: usize = 32;
const MAX_SOURCE_RACE_RETRIES: usize = 2;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StructuralConfig {
    pub max_files: usize,
    pub max_file_bytes: u64,
    pub batch_files: usize,
}

impl Default for StructuralConfig {
    fn default() -> Self {
        Self {
            max_files: DEFAULT_MAX_FILES,
            max_file_bytes: DEFAULT_MAX_FILE_BYTES,
            batch_files: DEFAULT_BATCH_FILES,
        }
    }
}

impl StructuralConfig {
    fn validate(&self) -> Result<(), RepoError> {
        if self.max_files == 0 || self.max_file_bytes == 0 || self.batch_files == 0 {
            return Err(RepoError::InvalidSearch(
                "structural index bounds must be positive".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SymbolRecord {
    pub repository_id: String,
    pub relative_path: PathBuf,
    pub source_digest: String,
    pub parser_fingerprint: String,
    pub schema_fingerprint: String,
    pub language: String,
    pub kind: String,
    pub name: String,
    pub start_byte: usize,
    pub end_byte: usize,
    pub start_line: u64,
    pub end_line: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DependencyEdge {
    pub repository_id: String,
    pub source_path: PathBuf,
    pub source_digest: String,
    pub parser_fingerprint: String,
    pub schema_fingerprint: String,
    pub language: String,
    pub relation: String,
    pub target: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StructuralSnapshot {
    pub repository_id: String,
    pub generation: u64,
    pub source_manifest_digest: String,
    pub parser_fingerprint: String,
    pub schema_fingerprint: String,
    pub supported_files: usize,
    pub unsupported_files: usize,
    pub symbols: usize,
    pub dependency_edges: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StructuralTelemetry {
    pub parsed_files: usize,
    pub affected_neighbor_files: usize,
    pub peak_source_bytes: u64,
    pub parser_batch_file_limit: usize,
    pub max_live_asts: usize,
    pub peak_process_rss_bytes: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StructuralRefreshReport {
    pub changed_files: usize,
    pub deleted_files: usize,
    pub unchanged_files: usize,
    pub unsupported_files: usize,
    pub reparsed_paths: Vec<PathBuf>,
    pub affected_neighbor_paths: Vec<PathBuf>,
    pub snapshot: StructuralSnapshot,
    pub telemetry: StructuralTelemetry,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StructuralLookup<T> {
    Indexed(Vec<T>),
    UnsupportedLanguage { path: PathBuf },
}

pub trait SymbolIndex {
    fn definitions(&mut self, name: &str) -> Result<Vec<SymbolRecord>, RepoError>;
}

pub trait DependencyGraph {
    fn import_neighborhood(&mut self, path: &Path) -> Result<Vec<DependencyEdge>, RepoError>;
}

pub trait StructuralRetriever: SymbolIndex + DependencyGraph {
    fn structural_for_path(
        &mut self,
        path: &Path,
    ) -> Result<StructuralLookup<SymbolRecord>, RepoError>;
}

#[derive(Debug, Clone)]
struct SourceFile {
    digest: String,
    language: Option<SupportedLanguage>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SupportedLanguage {
    Rust,
    TypeScript,
    Tsx,
}

impl SupportedLanguage {
    fn label(self) -> &'static str {
        match self {
            Self::Rust => "rust",
            Self::TypeScript => "typescript",
            Self::Tsx => "tsx",
        }
    }

    fn grammar(self) -> Language {
        match self {
            Self::Rust => tree_sitter_rust::LANGUAGE.into(),
            Self::TypeScript => tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
            Self::Tsx => tree_sitter_typescript::LANGUAGE_TSX.into(),
        }
    }
}

pub struct StructuralIndex<'a> {
    registry: &'a ProjectRegistry,
    repository_id: String,
    connection: Connection,
    config: StructuralConfig,
}

impl<'a> StructuralIndex<'a> {
    pub fn open(
        registry: &'a ProjectRegistry,
        repository_id: &str,
        db_path: impl AsRef<Path>,
        config: StructuralConfig,
    ) -> Result<Self, RepoError> {
        config.validate()?;
        let _ = registry
            .repository(repository_id)
            .ok_or_else(|| RepoError::UnknownRepository(repository_id.to_owned()))?;
        let db_path = db_path.as_ref();
        if let Some(parent) = db_path.parent() {
            fs::create_dir_all(parent)?;
        }
        let connection = Connection::open(db_path).map_err(sqlite_error)?;
        let mut index = Self {
            registry,
            repository_id: repository_id.to_owned(),
            connection,
            config,
        };
        index.ensure_compatible_schema()?;
        Ok(index)
    }

    pub fn rebuild(&mut self) -> Result<StructuralRefreshReport, RepoError> {
        self.drop_derived_schema()?;
        self.create_schema()?;
        self.refresh()
    }

    pub fn refresh(&mut self) -> Result<StructuralRefreshReport, RepoError> {
        self.refresh_with_retry(0)
    }

    fn refresh_with_retry(&mut self, retry: usize) -> Result<StructuralRefreshReport, RepoError> {
        let repository = self
            .registry
            .repository(&self.repository_id)
            .ok_or_else(|| RepoError::UnknownRepository(self.repository_id.clone()))?;
        let current = scan_sources(&repository.root, &self.config)?;
        let existing = load_manifest(&self.connection)?;
        let current_supported: BTreeMap<_, _> = current
            .iter()
            .filter(|(_, source)| source.language.is_some())
            .map(|(path, source)| (path.clone(), source.digest.clone()))
            .collect();
        let current_paths: BTreeSet<_> = current_supported.keys().cloned().collect();
        let existing_paths: BTreeSet<_> = existing.keys().cloned().collect();
        let deleted = existing_paths
            .difference(&current_paths)
            .cloned()
            .collect::<Vec<_>>();
        let changed = current_supported
            .iter()
            .filter_map(|(path, digest)| {
                (existing.get(path) != Some(digest)).then_some(path.clone())
            })
            .collect::<Vec<_>>();
        let unchanged_files = current_supported.len().saturating_sub(changed.len());
        let affected_neighbors = affected_neighbor_paths(&self.connection, &changed, &deleted)?;
        let mut parse_paths = BTreeSet::new();
        parse_paths.extend(changed.iter().cloned());
        parse_paths.extend(affected_neighbors.iter().cloned());
        parse_paths.retain(|path| current_supported.contains_key(path));

        let mut peak_source_bytes = 0_u64;
        let mut parsed_files = 0_usize;
        let mut peak_process_rss_bytes = None::<u64>;
        for batch in parse_paths
            .iter()
            .cloned()
            .collect::<Vec<_>>()
            .chunks(self.config.batch_files)
        {
            for path in batch {
                let source = current.get(path).ok_or_else(|| {
                    RepoError::InvalidSearch(
                        "structural source disappeared during refresh".to_owned(),
                    )
                })?;
                let language = source.language.ok_or_else(|| {
                    RepoError::InvalidSearch("unsupported file entered parser batch".to_owned())
                })?;
                let actual = fs::read(repository.root.join(path))?;
                let actual_digest = sha256_prefixed(&actual);
                if actual_digest != source.digest {
                    if retry < MAX_SOURCE_RACE_RETRIES {
                        return self.refresh_with_retry(retry + 1);
                    }
                    return Err(RepoError::StaleFileHash {
                        path: path.clone(),
                        expected: source.digest.clone(),
                        actual: actual_digest,
                    });
                }
                peak_source_bytes =
                    peak_source_bytes.max(u64::try_from(actual.len()).unwrap_or(u64::MAX));
                let parsed =
                    parse_source(path, &actual, &source.digest, language, &self.repository_id)?;
                if let Some(rss) = parsed.process_rss_bytes {
                    peak_process_rss_bytes =
                        Some(peak_process_rss_bytes.map_or(rss, |peak| peak.max(rss)));
                }
                let transaction = self.connection.transaction().map_err(sqlite_error)?;
                invalidate_path(&transaction, path)?;
                write_parsed(&transaction, path, &source.digest, language, &parsed)?;
                transaction.commit().map_err(sqlite_error)?;
                parsed_files = parsed_files.saturating_add(1);
            }
        }
        if !deleted.is_empty() {
            let transaction = self.connection.transaction().map_err(sqlite_error)?;
            for path in &deleted {
                invalidate_path(&transaction, path)?;
            }
            transaction.commit().map_err(sqlite_error)?;
        }

        let verified = scan_sources(&repository.root, &self.config)?;
        let verified_supported: BTreeMap<_, _> = verified
            .iter()
            .filter(|(_, source)| source.language.is_some())
            .map(|(path, source)| (path.clone(), source.digest.clone()))
            .collect();
        if verified_supported != current_supported {
            if retry < MAX_SOURCE_RACE_RETRIES {
                return self.refresh_with_retry(retry + 1);
            }
            return Err(RepoError::InvalidSearch(
                "structural source changed repeatedly during bounded refresh".to_owned(),
            ));
        }
        let unsupported_files = verified
            .values()
            .filter(|source| source.language.is_none())
            .count();
        let snapshot = self.publish_snapshot(&verified_supported, unsupported_files)?;
        let affected_neighbor_files = affected_neighbors.len();
        Ok(StructuralRefreshReport {
            changed_files: changed.len(),
            deleted_files: deleted.len(),
            unchanged_files,
            unsupported_files,
            reparsed_paths: parse_paths.into_iter().collect(),
            affected_neighbor_paths: affected_neighbors.into_iter().collect(),
            snapshot,
            telemetry: StructuralTelemetry {
                parsed_files,
                affected_neighbor_files,
                peak_source_bytes,
                parser_batch_file_limit: self.config.batch_files,
                max_live_asts: usize::from(parsed_files > 0),
                peak_process_rss_bytes,
            },
        })
    }

    pub fn snapshot(&self) -> Result<Option<StructuralSnapshot>, RepoError> {
        self.connection
            .query_row(
                "SELECT value_text FROM structural_metadata WHERE key='snapshot'",
                [],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(sqlite_error)?
            .map(|raw| serde_json::from_str(&raw).map_err(RepoError::Serialization))
            .transpose()
    }

    fn ensure_fresh(&mut self) -> Result<(), RepoError> {
        let repository = self
            .registry
            .repository(&self.repository_id)
            .ok_or_else(|| RepoError::UnknownRepository(self.repository_id.clone()))?;
        let supported = current_supported_manifest(&repository.root, &self.config)?;
        let digest = source_manifest_digest(&supported);
        if self.snapshot()?.as_ref().is_none_or(|snapshot| {
            snapshot.source_manifest_digest != digest
                || snapshot.supported_files != supported.len()
                || snapshot.parser_fingerprint != parser_fingerprint()
                || snapshot.schema_fingerprint != STRUCTURAL_SCHEMA_FINGERPRINT
        }) {
            self.refresh()?;
        }
        Ok(())
    }

    fn source_manifest_is_current(&self) -> Result<bool, RepoError> {
        let repository = self
            .registry
            .repository(&self.repository_id)
            .ok_or_else(|| RepoError::UnknownRepository(self.repository_id.clone()))?;
        let supported = current_supported_manifest(&repository.root, &self.config)?;
        Ok(self
            .snapshot()?
            .as_ref()
            .is_some_and(|snapshot| snapshot_matches_supported_manifest(snapshot, &supported)))
    }

    fn validate_records_fresh(
        &self,
        paths: impl Iterator<Item = PathBuf>,
    ) -> Result<bool, RepoError> {
        let repository = self
            .registry
            .repository(&self.repository_id)
            .ok_or_else(|| RepoError::UnknownRepository(self.repository_id.clone()))?;
        for path in paths.collect::<BTreeSet<_>>() {
            let expected: Option<String> = self
                .connection
                .query_row(
                    "SELECT source_digest FROM structural_files WHERE path=?1",
                    [path.to_string_lossy().as_ref()],
                    |row| row.get(0),
                )
                .optional()
                .map_err(sqlite_error)?;
            let actual = fs::read(repository.root.join(&path))
                .ok()
                .map(|bytes| sha256_prefixed(&bytes));
            if expected != actual {
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn publish_snapshot(
        &mut self,
        supported: &BTreeMap<PathBuf, String>,
        unsupported_files: usize,
    ) -> Result<StructuralSnapshot, RepoError> {
        let generation = self
            .snapshot()?
            .map_or(1, |snapshot| snapshot.generation.saturating_add(1));
        let symbols = count_rows(&self.connection, "structural_symbols")?;
        let dependency_edges = count_rows(&self.connection, "structural_edges")?;
        let snapshot = StructuralSnapshot {
            repository_id: self.repository_id.clone(),
            generation,
            source_manifest_digest: source_manifest_digest(supported),
            parser_fingerprint: parser_fingerprint(),
            schema_fingerprint: STRUCTURAL_SCHEMA_FINGERPRINT.to_owned(),
            supported_files: supported.len(),
            unsupported_files,
            symbols,
            dependency_edges,
        };
        self.connection
            .execute(
                "INSERT INTO structural_metadata(key,value_text) VALUES('snapshot',?1) ON CONFLICT(key) DO UPDATE SET value_text=excluded.value_text",
                [serde_json::to_string(&snapshot)?],
            )
            .map_err(sqlite_error)?;
        Ok(snapshot)
    }

    fn ensure_compatible_schema(&mut self) -> Result<(), RepoError> {
        let version = self
            .connection
            .query_row(
                "SELECT value_int FROM structural_metadata WHERE key='schema_version'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .optional();
        let version: Option<i64> = version.unwrap_or_default();
        let parser = self
            .connection
            .query_row(
                "SELECT value_text FROM structural_metadata WHERE key='parser_fingerprint'",
                [],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .unwrap_or(None);
        let schema = self
            .connection
            .query_row(
                "SELECT value_text FROM structural_metadata WHERE key='schema_fingerprint'",
                [],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .unwrap_or(None);
        if version == Some(STRUCTURAL_SCHEMA_VERSION)
            && parser.as_deref() == Some(parser_fingerprint().as_str())
            && schema.as_deref() == Some(STRUCTURAL_SCHEMA_FINGERPRINT)
        {
            return Ok(());
        }
        self.drop_derived_schema()?;
        self.create_schema()
    }

    fn drop_derived_schema(&mut self) -> Result<(), RepoError> {
        self.connection
            .execute_batch(
                "DROP TABLE IF EXISTS structural_edges;
                 DROP TABLE IF EXISTS structural_symbols;
                 DROP TABLE IF EXISTS structural_files;
                 DROP TABLE IF EXISTS structural_metadata;",
            )
            .map_err(sqlite_error)
    }

    fn create_schema(&mut self) -> Result<(), RepoError> {
        self.connection
            .execute_batch(
                "CREATE TABLE structural_metadata(key TEXT PRIMARY KEY,value_int INTEGER,value_text TEXT);
                 CREATE TABLE structural_files(path TEXT PRIMARY KEY,source_digest TEXT NOT NULL,language TEXT NOT NULL);
                 CREATE TABLE structural_symbols(
                   id INTEGER PRIMARY KEY,path TEXT NOT NULL,source_digest TEXT NOT NULL,language TEXT NOT NULL,
                   kind TEXT NOT NULL,name TEXT NOT NULL,start_byte INTEGER NOT NULL,end_byte INTEGER NOT NULL,
                   start_line INTEGER NOT NULL,end_line INTEGER NOT NULL);
                 CREATE INDEX structural_symbols_name_idx ON structural_symbols(name,path);
                 CREATE INDEX structural_symbols_path_idx ON structural_symbols(path);
                 CREATE TABLE structural_edges(
                   id INTEGER PRIMARY KEY,source_path TEXT NOT NULL,source_digest TEXT NOT NULL,language TEXT NOT NULL,
                   relation TEXT NOT NULL,target TEXT NOT NULL);
                 CREATE INDEX structural_edges_source_idx ON structural_edges(source_path);
                 CREATE INDEX structural_edges_target_idx ON structural_edges(target);",
            )
            .map_err(sqlite_error)?;
        self.connection
            .execute(
                "INSERT INTO structural_metadata(key,value_int) VALUES('schema_version',?1)",
                [STRUCTURAL_SCHEMA_VERSION],
            )
            .map_err(sqlite_error)?;
        self.connection
            .execute(
                "INSERT INTO structural_metadata(key,value_text) VALUES('schema_fingerprint',?1)",
                [STRUCTURAL_SCHEMA_FINGERPRINT],
            )
            .map_err(sqlite_error)?;
        self.connection
            .execute(
                "INSERT INTO structural_metadata(key,value_text) VALUES('parser_fingerprint',?1)",
                [parser_fingerprint()],
            )
            .map_err(sqlite_error)?;
        Ok(())
    }
}

impl SymbolIndex for StructuralIndex<'_> {
    fn definitions(&mut self, name: &str) -> Result<Vec<SymbolRecord>, RepoError> {
        if name.trim().is_empty() {
            return Err(RepoError::InvalidSearch(
                "symbol name must not be empty".to_owned(),
            ));
        }
        for attempt in 0..=MAX_SOURCE_RACE_RETRIES {
            self.ensure_fresh()?;
            let rows = query_symbols(&self.connection, &self.repository_id, Some(name), None)?;
            let rows_current =
                self.validate_records_fresh(rows.iter().map(|row| row.relative_path.clone()))?;
            let manifest_current = self.source_manifest_is_current()?;
            if rows_current && manifest_current {
                return Ok(rows);
            }
            if attempt == MAX_SOURCE_RACE_RETRIES {
                break;
            }
            self.refresh()?;
        }
        Err(RepoError::InvalidSearch(
            "symbol query source changed repeatedly during bounded validation".to_owned(),
        ))
    }
}

impl DependencyGraph for StructuralIndex<'_> {
    fn import_neighborhood(&mut self, path: &Path) -> Result<Vec<DependencyEdge>, RepoError> {
        for attempt in 0..=MAX_SOURCE_RACE_RETRIES {
            self.ensure_fresh()?;
            let rows = query_edges(&self.connection, &self.repository_id, path)?;
            let rows_current =
                self.validate_records_fresh(rows.iter().map(|row| row.source_path.clone()))?;
            let manifest_current = self.source_manifest_is_current()?;
            if rows_current && manifest_current {
                return Ok(rows);
            }
            if attempt == MAX_SOURCE_RACE_RETRIES {
                break;
            }
            self.refresh()?;
        }
        Err(RepoError::InvalidSearch(
            "dependency query source changed repeatedly during bounded validation".to_owned(),
        ))
    }
}

impl StructuralRetriever for StructuralIndex<'_> {
    fn structural_for_path(
        &mut self,
        path: &Path,
    ) -> Result<StructuralLookup<SymbolRecord>, RepoError> {
        if language_for_path(path).is_none() {
            return Ok(StructuralLookup::UnsupportedLanguage {
                path: path.to_path_buf(),
            });
        }
        for attempt in 0..=MAX_SOURCE_RACE_RETRIES {
            self.ensure_fresh()?;
            let rows = query_symbols(&self.connection, &self.repository_id, None, Some(path))?;
            let rows_current =
                self.validate_records_fresh(rows.iter().map(|row| row.relative_path.clone()))?;
            let manifest_current = self.source_manifest_is_current()?;
            if rows_current && manifest_current {
                return Ok(StructuralLookup::Indexed(rows));
            }
            if attempt == MAX_SOURCE_RACE_RETRIES {
                break;
            }
            self.refresh()?;
        }
        Err(RepoError::InvalidSearch(
            "structural path query source changed repeatedly during bounded validation".to_owned(),
        ))
    }
}

#[derive(Debug)]
struct ParsedFile {
    symbols: Vec<ParsedSymbol>,
    edges: Vec<ParsedEdge>,
    process_rss_bytes: Option<u64>,
}

#[derive(Debug)]
struct ParsedSymbol {
    kind: String,
    name: String,
    start_byte: usize,
    end_byte: usize,
    start_line: u64,
    end_line: u64,
}

#[derive(Debug)]
struct ParsedEdge {
    relation: String,
    target: String,
}

fn parse_source(
    path: &Path,
    bytes: &[u8],
    source_digest: &str,
    language: SupportedLanguage,
    _repository_id: &str,
) -> Result<ParsedFile, RepoError> {
    let mut parser = Parser::new();
    parser.set_language(&language.grammar()).map_err(|error| {
        RepoError::InvalidSearch(format!("tree-sitter language error: {error}"))
    })?;
    let tree = parser.parse(bytes, None).ok_or_else(|| {
        RepoError::InvalidSearch(format!(
            "tree-sitter parse returned no tree for {}",
            path.display()
        ))
    })?;
    let process_rss_bytes = process_rss_bytes();
    let mut symbols = Vec::new();
    let mut edges = Vec::new();
    walk_tree(tree.root_node(), bytes, language, &mut symbols, &mut edges);
    let _ = source_digest;
    Ok(ParsedFile {
        symbols,
        edges,
        process_rss_bytes,
    })
}

fn walk_tree(
    node: Node<'_>,
    bytes: &[u8],
    language: SupportedLanguage,
    symbols: &mut Vec<ParsedSymbol>,
    edges: &mut Vec<ParsedEdge>,
) {
    if is_definition_kind(language, node.kind())
        && let Some(name_node) = node.child_by_field_name("name")
        && let Ok(name) = name_node.utf8_text(bytes)
        && !name.trim().is_empty()
    {
        symbols.push(ParsedSymbol {
            kind: node.kind().to_owned(),
            name: name.to_owned(),
            start_byte: node.start_byte(),
            end_byte: node.end_byte(),
            start_line: u64::try_from(node.start_position().row.saturating_add(1))
                .unwrap_or(u64::MAX),
            end_line: u64::try_from(node.end_position().row.saturating_add(1)).unwrap_or(u64::MAX),
        });
    }
    if let Some(edge) = import_edge(language, node, bytes) {
        edges.push(edge);
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        walk_tree(child, bytes, language, symbols, edges);
    }
}

fn is_definition_kind(language: SupportedLanguage, kind: &str) -> bool {
    match language {
        SupportedLanguage::Rust => matches!(
            kind,
            "function_item"
                | "struct_item"
                | "enum_item"
                | "trait_item"
                | "type_item"
                | "const_item"
                | "static_item"
                | "mod_item"
        ),
        SupportedLanguage::TypeScript | SupportedLanguage::Tsx => matches!(
            kind,
            "function_declaration"
                | "class_declaration"
                | "interface_declaration"
                | "type_alias_declaration"
                | "enum_declaration"
                | "method_definition"
        ),
    }
}

fn import_edge(language: SupportedLanguage, node: Node<'_>, bytes: &[u8]) -> Option<ParsedEdge> {
    match language {
        SupportedLanguage::Rust if node.kind() == "use_declaration" => {
            let text = node.utf8_text(bytes).ok()?.trim();
            let target = text.strip_prefix("use ")?.trim_end_matches(';').trim();
            (!target.is_empty()).then(|| ParsedEdge {
                relation: "import".to_owned(),
                target: target.to_owned(),
            })
        }
        SupportedLanguage::Rust if node.kind() == "mod_item" => {
            let name = node.child_by_field_name("name")?.utf8_text(bytes).ok()?;
            Some(ParsedEdge {
                relation: "module".to_owned(),
                target: name.to_owned(),
            })
        }
        SupportedLanguage::TypeScript | SupportedLanguage::Tsx
            if node.kind() == "import_statement" || node.kind() == "export_statement" =>
        {
            let source = node.child_by_field_name("source")?;
            let raw = source.utf8_text(bytes).ok()?;
            Some(ParsedEdge {
                relation: if node.kind() == "import_statement" {
                    "import"
                } else {
                    "reexport"
                }
                .to_owned(),
                target: raw.trim_matches(['\'', '"']).to_owned(),
            })
        }
        _ => None,
    }
}

fn write_parsed(
    transaction: &Transaction<'_>,
    path: &Path,
    digest: &str,
    language: SupportedLanguage,
    parsed: &ParsedFile,
) -> Result<(), RepoError> {
    let path = path.to_string_lossy();
    transaction
        .execute(
            "INSERT INTO structural_files(path,source_digest,language) VALUES(?1,?2,?3)",
            params![path.as_ref(), digest, language.label()],
        )
        .map_err(sqlite_error)?;
    for symbol in &parsed.symbols {
        transaction
            .execute(
                "INSERT INTO structural_symbols(path,source_digest,language,kind,name,start_byte,end_byte,start_line,end_line) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)",
                params![path.as_ref(), digest, language.label(), symbol.kind, symbol.name, symbol.start_byte, symbol.end_byte, symbol.start_line, symbol.end_line],
            )
            .map_err(sqlite_error)?;
    }
    for edge in &parsed.edges {
        transaction
            .execute(
                "INSERT INTO structural_edges(source_path,source_digest,language,relation,target) VALUES(?1,?2,?3,?4,?5)",
                params![path.as_ref(), digest, language.label(), edge.relation, edge.target],
            )
            .map_err(sqlite_error)?;
    }
    Ok(())
}

fn invalidate_path(transaction: &Transaction<'_>, path: &Path) -> Result<(), RepoError> {
    let path = path.to_string_lossy();
    transaction
        .execute(
            "DELETE FROM structural_edges WHERE source_path=?1",
            [path.as_ref()],
        )
        .map_err(sqlite_error)?;
    transaction
        .execute(
            "DELETE FROM structural_symbols WHERE path=?1",
            [path.as_ref()],
        )
        .map_err(sqlite_error)?;
    transaction
        .execute(
            "DELETE FROM structural_files WHERE path=?1",
            [path.as_ref()],
        )
        .map_err(sqlite_error)?;
    Ok(())
}

fn scan_sources(
    root: &Path,
    config: &StructuralConfig,
) -> Result<BTreeMap<PathBuf, SourceFile>, RepoError> {
    let mut paths = Vec::new();
    collect_regular_files(root, Path::new(""), config.max_files, &mut paths)?;
    paths.sort();
    let mut sources = BTreeMap::new();
    for path in paths {
        let metadata = fs::metadata(root.join(&path))?;
        if metadata.len() > config.max_file_bytes {
            continue;
        }
        let bytes = fs::read(root.join(&path))?;
        if std::str::from_utf8(&bytes).is_err() {
            continue;
        }
        sources.insert(
            path.clone(),
            SourceFile {
                digest: sha256_prefixed(&bytes),
                language: language_for_path(&path),
            },
        );
    }
    Ok(sources)
}

fn current_supported_manifest(
    root: &Path,
    config: &StructuralConfig,
) -> Result<BTreeMap<PathBuf, String>, RepoError> {
    Ok(scan_sources(root, config)?
        .into_iter()
        .filter_map(|(path, source)| source.language.map(|_| (path, source.digest)))
        .collect())
}

fn snapshot_matches_supported_manifest(
    snapshot: &StructuralSnapshot,
    supported: &BTreeMap<PathBuf, String>,
) -> bool {
    snapshot.source_manifest_digest == source_manifest_digest(supported)
        && snapshot.supported_files == supported.len()
        && snapshot.parser_fingerprint == parser_fingerprint()
        && snapshot.schema_fingerprint == STRUCTURAL_SCHEMA_FINGERPRINT
}

fn language_for_path(path: &Path) -> Option<SupportedLanguage> {
    match path.extension().and_then(|ext| ext.to_str()) {
        Some("rs") => Some(SupportedLanguage::Rust),
        Some("ts") => Some(SupportedLanguage::TypeScript),
        Some("tsx") => Some(SupportedLanguage::Tsx),
        _ => None,
    }
}

fn load_manifest(connection: &Connection) -> Result<BTreeMap<PathBuf, String>, RepoError> {
    let mut statement = connection
        .prepare("SELECT path,source_digest FROM structural_files ORDER BY path")
        .map_err(sqlite_error)?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                PathBuf::from(row.get::<_, String>(0)?),
                row.get::<_, String>(1)?,
            ))
        })
        .map_err(sqlite_error)?;
    rows.collect::<Result<BTreeMap<_, _>, _>>()
        .map_err(sqlite_error)
}

fn source_manifest_digest(sources: &BTreeMap<PathBuf, String>) -> String {
    let mut bytes = Vec::new();
    for (path, digest) in sources {
        bytes.extend_from_slice(path.as_os_str().as_encoded_bytes());
        bytes.push(0);
        bytes.extend_from_slice(digest.as_bytes());
        bytes.push(0);
    }
    sha256_prefixed(&bytes)
}

fn affected_neighbor_paths(
    connection: &Connection,
    changed: &[PathBuf],
    deleted: &[PathBuf],
) -> Result<BTreeSet<PathBuf>, RepoError> {
    let mut module_keys = BTreeSet::new();
    for path in changed.iter().chain(deleted.iter()) {
        module_keys.extend(module_keys_for_path(path));
    }
    let mut output = BTreeSet::new();
    let mut statement = connection
        .prepare("SELECT source_path,target FROM structural_edges ORDER BY source_path,target")
        .map_err(sqlite_error)?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                PathBuf::from(row.get::<_, String>(0)?),
                row.get::<_, String>(1)?,
            ))
        })
        .map_err(sqlite_error)?;
    for row in rows {
        let (source_path, target) = row.map_err(sqlite_error)?;
        if module_keys.iter().any(|key| target_matches(&target, key)) {
            output.insert(source_path);
        }
    }
    let existing_paths = load_manifest(connection)?.into_keys().collect::<Vec<_>>();
    for path in existing_paths {
        if is_test_path(&path)
            && changed
                .iter()
                .chain(deleted.iter())
                .any(|changed_path| same_stem_family(&path, changed_path))
        {
            output.insert(path);
        }
    }
    for path in changed.iter().chain(deleted.iter()) {
        output.remove(path);
    }
    Ok(output)
}

fn module_keys_for_path(path: &Path) -> BTreeSet<String> {
    let mut keys = BTreeSet::new();
    let no_ext = path.with_extension("");
    let components = no_ext
        .iter()
        .filter_map(|part| part.to_str())
        .collect::<Vec<_>>();
    if let Some(stem) = no_ext.file_name().and_then(|name| name.to_str()) {
        keys.insert(stem.to_owned());
        keys.insert(format!("./{stem}"));
        keys.insert(format!("../{stem}"));
    }
    if !components.is_empty() {
        keys.insert(components.join("::"));
        keys.insert(components.join("/"));
    }
    keys
}

fn target_matches(target: &str, key: &str) -> bool {
    target == key
        || target.ends_with(&format!("::{key}"))
        || target.ends_with(&format!("/{key}"))
        || target.trim_start_matches("./") == key.trim_start_matches("./")
}

fn is_test_path(path: &Path) -> bool {
    let text = path.to_string_lossy();
    text.contains("/tests/")
        || text.ends_with("_test.rs")
        || text.ends_with(".test.ts")
        || text.ends_with(".test.tsx")
        || text.ends_with(".spec.ts")
        || text.ends_with(".spec.tsx")
}

fn same_stem_family(left: &Path, right: &Path) -> bool {
    let normalize = |path: &Path| {
        path.file_stem()
            .and_then(|stem| stem.to_str())
            .unwrap_or_default()
            .trim_end_matches(".test")
            .trim_end_matches(".spec")
            .trim_end_matches("_test")
            .to_owned()
    };
    let left = normalize(left);
    !left.is_empty() && left == normalize(right)
}

fn query_symbols(
    connection: &Connection,
    repository_id: &str,
    name: Option<&str>,
    path: Option<&Path>,
) -> Result<Vec<SymbolRecord>, RepoError> {
    let (sql, value) = if let Some(name) = name {
        (
            "SELECT path,source_digest,language,kind,name,start_byte,end_byte,start_line,end_line FROM structural_symbols WHERE name=?1 ORDER BY path,start_byte",
            name.to_owned(),
        )
    } else if let Some(path) = path {
        (
            "SELECT path,source_digest,language,kind,name,start_byte,end_byte,start_line,end_line FROM structural_symbols WHERE path=?1 ORDER BY start_byte",
            path.to_string_lossy().into_owned(),
        )
    } else {
        return Ok(Vec::new());
    };
    let mut statement = connection.prepare(sql).map_err(sqlite_error)?;
    let rows = statement
        .query_map([value], |row| {
            Ok(SymbolRecord {
                repository_id: repository_id.to_owned(),
                relative_path: PathBuf::from(row.get::<_, String>(0)?),
                source_digest: row.get(1)?,
                parser_fingerprint: parser_fingerprint(),
                schema_fingerprint: STRUCTURAL_SCHEMA_FINGERPRINT.to_owned(),
                language: row.get(2)?,
                kind: row.get(3)?,
                name: row.get(4)?,
                start_byte: row.get(5)?,
                end_byte: row.get(6)?,
                start_line: row.get(7)?,
                end_line: row.get(8)?,
            })
        })
        .map_err(sqlite_error)?;
    rows.collect::<Result<Vec<_>, _>>().map_err(sqlite_error)
}

fn query_edges(
    connection: &Connection,
    repository_id: &str,
    path: &Path,
) -> Result<Vec<DependencyEdge>, RepoError> {
    let mut statement = connection
        .prepare("SELECT source_path,source_digest,language,relation,target FROM structural_edges WHERE source_path=?1 ORDER BY relation,target")
        .map_err(sqlite_error)?;
    let rows = statement
        .query_map([path.to_string_lossy().as_ref()], |row| {
            Ok(DependencyEdge {
                repository_id: repository_id.to_owned(),
                source_path: PathBuf::from(row.get::<_, String>(0)?),
                source_digest: row.get(1)?,
                parser_fingerprint: parser_fingerprint(),
                schema_fingerprint: STRUCTURAL_SCHEMA_FINGERPRINT.to_owned(),
                language: row.get(2)?,
                relation: row.get(3)?,
                target: row.get(4)?,
            })
        })
        .map_err(sqlite_error)?;
    rows.collect::<Result<Vec<_>, _>>().map_err(sqlite_error)
}

fn count_rows(connection: &Connection, table: &str) -> Result<usize, RepoError> {
    let sql = format!("SELECT count(*) FROM {table}");
    let value: i64 = connection
        .query_row(&sql, [], |row| row.get(0))
        .map_err(sqlite_error)?;
    Ok(usize::try_from(value).unwrap_or(usize::MAX))
}

fn process_rss_bytes() -> Option<u64> {
    let pid = std::process::id().to_string();
    let output = Command::new("/bin/ps")
        .args(["-o", "rss=", "-p", &pid])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8(output.stdout).ok()?;
    text.trim()
        .parse::<u64>()
        .ok()
        .map(|kib| kib.saturating_mul(1024))
}

fn parser_fingerprint() -> String {
    sha256_prefixed(PARSER_VERSION_MANIFEST.as_bytes())
}

#[allow(clippy::needless_pass_by_value)]
fn sqlite_error(error: rusqlite::Error) -> RepoError {
    let message = error.to_string();
    drop(error);
    RepoError::InvalidSearch(format!("structural SQLite error: {message}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn structural_zero_hit_post_query_manifest_revalidation_rejects_new_supported_source() {
        let mut supported =
            BTreeMap::from([(PathBuf::from("src/lib.rs"), "sha256:old-source".to_owned())]);
        let snapshot = StructuralSnapshot {
            repository_id: "repo.fixture".to_owned(),
            generation: 1,
            source_manifest_digest: source_manifest_digest(&supported),
            parser_fingerprint: parser_fingerprint(),
            schema_fingerprint: STRUCTURAL_SCHEMA_FINGERPRINT.to_owned(),
            supported_files: supported.len(),
            unsupported_files: 0,
            symbols: 0,
            dependency_edges: 0,
        };
        assert!(snapshot_matches_supported_manifest(&snapshot, &supported));

        supported.insert(
            PathBuf::from("src/new_term.rs"),
            "sha256:new-source".to_owned(),
        );
        assert!(!snapshot_matches_supported_manifest(&snapshot, &supported));
    }
}
