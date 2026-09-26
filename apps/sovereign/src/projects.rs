//! Project registration. Callers: `main.rs` CLI `project` and `/v2/projects`.
//! API: `resolve_git_root`, `register_project`, `create_project`, `open_folder`,
//! `choose_folder_dialog`, `set_active_project`.
//! Schema: `ProjectsV1` / `ProjectRecordV1` in `app_data.rs`.
//!
//! People who cannot code never see Git: `create_project` makes a folder with starter files and
//! version history, and `open_folder` adopts any folder, adding history only when it has none.
//! Project state always lives in app data, never inside the folder.

use crate::app_data::{AppData, ProjectRecordV1, ProjectsV1};
use sha2::{Digest, Sha256};
use sovereign_repo::{ManagedRepositoryInit, init_managed_repository};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

/// Folder under the home directory where new projects are created.
pub const PROJECTS_FOLDER_NAME: &str = "Sovereign Projects";
const MAX_PROJECT_NAME_CHARS: usize = 60;

const PINNED_GIT: &str = "/usr/bin/git";

/// Resolves an existing git work tree with pinned `/usr/bin/git`.
///
/// # Errors
/// Returns when the path is missing, is not a git work tree, or git fails.
pub fn resolve_git_root(root: &Path) -> Result<PathBuf, String> {
    if !root.is_absolute() {
        return Err("project root must be an absolute path".to_owned());
    }
    if !root.is_dir() {
        return Err(format!("project root does not exist: {}", root.display()));
    }
    let output = Command::new(PINNED_GIT)
        .args(["rev-parse", "--show-toplevel"])
        .current_dir(root)
        .output()
        .map_err(|error| format!("git rev-parse failed: {error}"))?;
    if !output.status.success() {
        return Err("path is not a git work tree".to_owned());
    }
    let text = String::from_utf8(output.stdout)
        .map_err(|_| "git rev-parse returned non-UTF-8".to_owned())?;
    let resolved = PathBuf::from(text.trim());
    if !resolved.is_absolute() {
        return Err("git toplevel was not absolute".to_owned());
    }
    Ok(resolved)
}

/// Registers a new project with state stored under app data, not inside the repo.
///
/// # Errors
/// Returns when the root is not a git work tree or the write fails.
pub fn register_project(
    data: &AppData,
    root: &Path,
    display_name: &str,
) -> Result<ProjectsV1, String> {
    let git_root = resolve_git_root(root)?;
    let name = display_name.trim();
    if name.is_empty() {
        return Err("display_name must be a non-empty string".to_owned());
    }
    let mut projects = data.load_projects().map_err(|error| error.to_string())?;
    if projects
        .projects
        .iter()
        .any(|project| Path::new(&project.root) == git_root)
    {
        return Err("a project for this repository is already registered".to_owned());
    }
    let project_id = new_project_id(&git_root, &projects);
    let project_dir = data.root().join("projects").join(&project_id);
    std::fs::create_dir_all(&project_dir).map_err(|error| error.to_string())?;
    let state_path = project_dir.join("state.sqlite3");
    let cas_root = project_dir.join("cas");
    if state_path.starts_with(&git_root) {
        return Err("new project state must live outside the repository root".to_owned());
    }
    let record = ProjectRecordV1 {
        project_id: project_id.clone(),
        display_name: name.to_owned(),
        root: git_root.to_string_lossy().into_owned(),
        state_path: state_path.to_string_lossy().into_owned(),
        cas_root: cas_root.to_string_lossy().into_owned(),
        created_at_ms: unix_millis(),
        managed: false,
    };
    projects.projects.push(record);
    if projects.active_project_id.is_none() {
        projects.active_project_id = Some(project_id);
    }
    data.save_projects(&projects)
        .map_err(|error| error.to_string())?;
    Ok(projects)
}

/// Unique, stable-looking id: a short digest of the folder and the creation time.
fn new_project_id(root: &Path, projects: &ProjectsV1) -> String {
    let mut attempt = 0_u32;
    loop {
        let digest =
            Sha256::digest(format!("{}\0{}\0{attempt}", root.display(), unix_millis()).as_bytes());
        let id = digest
            .iter()
            .take(6)
            .fold(String::from("project-"), |mut id, byte| {
                let _ = write!(id, "{byte:02x}");
                id
            });
        if !projects
            .projects
            .iter()
            .any(|project| project.project_id == id)
        {
            return id;
        }
        attempt += 1;
    }
}

/// Where new projects are created: `~/Sovereign Projects`.
///
/// # Errors
/// Returns when `HOME` is not set.
pub fn projects_home() -> Result<PathBuf, String> {
    std::env::var_os("HOME")
        .map(|home| PathBuf::from(home).join(PROJECTS_FOLDER_NAME))
        .ok_or_else(|| "HOME is not set".to_owned())
}

/// A folder name a person would expect from their project name, without path tricks.
fn folder_name(name: &str) -> Result<String, String> {
    let cleaned = name
        .chars()
        .map(|character| {
            if character.is_alphanumeric() || matches!(character, ' ' | '-' | '_' | '.') {
                character
            } else {
                ' '
            }
        })
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    let cleaned = cleaned.trim_matches('.').trim().to_owned();
    if cleaned.is_empty() {
        return Err("Give the project a name with at least one letter or number.".to_owned());
    }
    Ok(cleaned.chars().take(MAX_PROJECT_NAME_CHARS).collect())
}

fn register_folder(
    data: &AppData,
    root: &Path,
    display_name: &str,
    managed: bool,
) -> Result<(ProjectsV1, ProjectRecordV1), String> {
    let git_root = resolve_git_root(root)?;
    let mut projects = data.load_projects().map_err(|error| error.to_string())?;
    if let Some(existing) = projects
        .projects
        .iter()
        .find(|project| Path::new(&project.root) == git_root)
        .cloned()
    {
        projects.active_project_id = Some(existing.project_id.clone());
        data.save_projects(&projects)
            .map_err(|error| error.to_string())?;
        return Ok((projects, existing));
    }
    let project_id = new_project_id(&git_root, &projects);
    let project_dir = data.root().join("projects").join(&project_id);
    std::fs::create_dir_all(&project_dir).map_err(|error| error.to_string())?;
    let state_path = project_dir.join("state.sqlite3");
    if state_path.starts_with(&git_root) {
        return Err("project state must live outside the project folder".to_owned());
    }
    let record = ProjectRecordV1 {
        project_id: project_id.clone(),
        display_name: display_name.trim().to_owned(),
        root: git_root.to_string_lossy().into_owned(),
        state_path: state_path.to_string_lossy().into_owned(),
        cas_root: project_dir.join("cas").to_string_lossy().into_owned(),
        created_at_ms: unix_millis(),
        managed,
    };
    projects.projects.push(record.clone());
    projects.active_project_id = Some(project_id);
    data.save_projects(&projects)
        .map_err(|error| error.to_string())?;
    Ok((projects, record))
}

/// Creates `~/Sovereign Projects/<name>` (or `<name> 2`, ...) with starter files and version
/// history, registers it as a managed project, and makes it active.
///
/// # Errors
/// Returns a plain-language error when the name is unusable or the folder cannot be created.
pub fn create_project(
    data: &AppData,
    name: &str,
    parent: &Path,
) -> Result<(ProjectsV1, ProjectRecordV1), String> {
    let base_name = folder_name(name)?;
    std::fs::create_dir_all(parent)
        .map_err(|error| format!("Could not create {}: {error}", parent.display()))?;
    let mut folder = parent.join(&base_name);
    let mut suffix = 2;
    while std::fs::symlink_metadata(&folder).is_ok() {
        folder = parent.join(format!("{base_name} {suffix}"));
        suffix += 1;
    }
    std::fs::create_dir(&folder)
        .map_err(|error| format!("Could not create {}: {error}", folder.display()))?;
    crate::scaffold::write_starter_project(&folder, &base_name)
        .map_err(|error| format!("Could not write starter files: {error}"))?;
    init_managed_repository(&folder).map_err(|error| error.to_string())?;
    register_folder(data, &folder, &base_name, true)
}

/// Adopts an existing folder. A folder without version history gets it (and becomes managed);
/// a folder that already is a Git repository is used as it is and never auto-committed.
///
/// # Errors
/// Returns a plain-language error for a missing, relative, or unreadable folder.
pub fn open_folder(data: &AppData, root: &Path) -> Result<(ProjectsV1, ProjectRecordV1), String> {
    if !root.is_absolute() {
        return Err("Choose a folder with a full path.".to_owned());
    }
    if !root.is_dir() {
        return Err(format!("{} is not a folder.", root.display()));
    }
    let managed = match init_managed_repository(root).map_err(|error| error.to_string())? {
        ManagedRepositoryInit::Created { .. } => true,
        ManagedRepositoryInit::AlreadyRepository { .. } => false,
    };
    let display_name = root
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("Project")
        .to_owned();
    register_folder(data, root, &display_name, managed)
}

/// Shows the native macOS "Choose a folder" dialog. Returns `None` when the person cancels.
///
/// # Errors
/// Returns an error on other platforms or when the dialog cannot be shown.
pub fn choose_folder_dialog() -> Result<Option<PathBuf>, String> {
    if !cfg!(target_os = "macos") {
        return Err("The folder picker is available on macOS only.".to_owned());
    }
    let output = Command::new("/usr/bin/osascript")
        .args([
            "-e",
            "activate",
            "-e",
            "POSIX path of (choose folder with prompt \"Choose a folder for Sovereign to work in\")",
        ])
        .output()
        .map_err(|error| format!("Could not open the folder picker: {error}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if stderr.contains("-128") || stderr.to_ascii_lowercase().contains("cancel") {
            return Ok(None);
        }
        return Err(format!("The folder picker failed: {}", stderr.trim()));
    }
    let path = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    if path.is_empty() {
        return Ok(None);
    }
    Ok(Some(PathBuf::from(path)))
}

/// Active project record, if the index points at a known id.
#[must_use]
pub fn active_record(projects: &ProjectsV1) -> Option<&ProjectRecordV1> {
    let active_id = projects.active_project_id.as_ref()?;
    projects
        .projects
        .iter()
        .find(|project| &project.project_id == active_id)
}

/// Marks one registered project as active.
///
/// # Errors
/// Returns when the project id is unknown or the write fails.
pub fn set_active_project(data: &AppData, project_id: &str) -> Result<ProjectsV1, String> {
    let mut projects = data.load_projects().map_err(|error| error.to_string())?;
    if !projects
        .projects
        .iter()
        .any(|project| project.project_id == project_id)
    {
        return Err(format!("unknown project id {project_id}"));
    }
    projects.active_project_id = Some(project_id.to_owned());
    data.save_projects(&projects)
        .map_err(|error| error.to_string())?;
    Ok(projects)
}

fn unix_millis() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| {
            i64::try_from(duration.as_millis()).unwrap_or(0)
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_root(label: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        std::env::temp_dir().join(format!("sovereign-projects-{label}-{nonce}"))
    }

    fn init_git(dir: &Path) {
        fs::create_dir_all(dir).unwrap_or_else(|error| panic!("mkdir: {error}"));
        let status = Command::new(PINNED_GIT)
            .args(["init"])
            .current_dir(dir)
            .status()
            .unwrap_or_else(|error| panic!("git init: {error}"));
        assert!(status.success());
    }

    #[test]
    fn create_project_makes_a_managed_folder_with_history() {
        let root = temp_root("create");
        let data = AppData::open(&root.join("app")).unwrap_or_else(|error| panic!("{error}"));
        let parent = root.join("Sovereign Projects");
        let (projects, record) = create_project(&data, "My Budget / App", &parent)
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(record.managed);
        assert_eq!(record.display_name, "My Budget App");
        assert!(Path::new(&record.root).join("index.html").is_file());
        assert_eq!(
            projects.active_project_id.as_deref(),
            Some(record.project_id.as_str())
        );
        assert!(!Path::new(&record.state_path).starts_with(&record.root));
        // Same name again gets its own folder.
        let (_, second) = create_project(&data, "My Budget / App", &parent)
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(second.root.ends_with("My Budget App 2"));
        assert_ne!(second.project_id, record.project_id);
        assert!(create_project(&data, " /// ", &parent).is_err());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn open_folder_adds_history_only_when_missing_and_reopens_existing() {
        let root = temp_root("open");
        let data = AppData::open(&root.join("app")).unwrap_or_else(|error| panic!("{error}"));
        let plain = root.join("plain");
        fs::create_dir_all(&plain).unwrap_or_else(|error| panic!("{error}"));
        fs::write(plain.join("notes.txt"), "hi").unwrap_or_else(|error| panic!("{error}"));
        let (_, record) = open_folder(&data, &plain).unwrap_or_else(|error| panic!("{error}"));
        assert!(record.managed);
        let (_, again) = open_folder(&data, &plain).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(again.project_id, record.project_id);

        let repo = root.join("repo");
        fs::create_dir_all(&repo).unwrap_or_else(|error| panic!("{error}"));
        init_git(&repo);
        let (_, existing) = open_folder(&data, &repo).unwrap_or_else(|error| panic!("{error}"));
        assert!(
            !existing.managed,
            "an existing repository is never auto-committed"
        );
        assert!(open_folder(&data, Path::new("relative")).is_err());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn non_git_path_is_rejected() {
        let dir = temp_root("nongit");
        fs::create_dir_all(&dir).unwrap_or_else(|error| panic!("mkdir: {error}"));
        assert!(resolve_git_root(&dir).is_err());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn register_keeps_state_outside_repo() {
        let app_root = temp_root("app");
        let repo = temp_root("repo");
        init_git(&repo);
        let data = AppData::open(&app_root).unwrap_or_else(|error| panic!("open: {error}"));
        let projects = register_project(&data, &repo, "Demo")
            .unwrap_or_else(|error| panic!("register: {error}"));
        let record = projects
            .projects
            .first()
            .unwrap_or_else(|| panic!("missing project"));
        assert!(!Path::new(&record.state_path).starts_with(&repo));
        assert!(Path::new(&record.state_path).starts_with(&app_root));
        let _ = fs::remove_dir_all(app_root);
        let _ = fs::remove_dir_all(repo);
    }
}
