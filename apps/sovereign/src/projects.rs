//! Git-root project registration. Callers: `main.rs` CLI `project` and `/v2/projects`.
//! API: `resolve_git_root`, `register_project`, `activate_project`.
//! Schema: `ProjectsV1` / `ProjectRecordV1` in `app_data.rs`.
//! User instruction: implement the attached consumer product plan (CX-T09).

use crate::app_data::{AppData, ProjectRecordV1, ProjectsV1};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

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
    let project_id = format!("project-{}", projects.projects.len() + 1);
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
    };
    projects.projects.push(record);
    if projects.active_project_id.is_none() {
        projects.active_project_id = Some(project_id);
    }
    data.save_projects(&projects)
        .map_err(|error| error.to_string())?;
    Ok(projects)
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
