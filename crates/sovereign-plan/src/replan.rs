use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

/// Stable Plan IR assumption that may authorize replanning only after its exact
/// clause is invalidated by Controller-verified evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanAssumption {
    pub assumption_id: String,
    pub text: String,
    pub invalidation_scope: ReplanScope,
    pub basis_evidence: Vec<PlanAssumptionEvidence>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fingerprints: Vec<String>,
}

/// Digest-bound evidence reference used by a stable plan assumption.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanAssumptionEvidence {
    pub evidence_id: String,
    pub digest: String,
    pub locator: String,
    pub trust: String,
    pub freshness: String,
}

/// The smallest deterministic scope that may be superseded by a plan failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplanScope {
    Task,
    DependencyBranch,
    Plan,
}

/// Trusted Controller input for revision N -> N+1 compilation through the same
/// canonical [`crate::PlanCompiler::compile`] path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanReplanInput {
    pub previous_plan: Value,
    pub previous_plan_digest: String,
    pub scope: ReplanScope,
    pub invalidated_contract_ids: Vec<String>,
    pub affected_task_ids: Vec<String>,
}

/// Immutable structural difference between directly adjacent plan revisions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanRevisionDiff {
    pub plan_id: String,
    pub from_revision: u32,
    pub to_revision: u32,
    pub from_plan_digest: String,
    pub to_plan_digest: String,
    pub scope: ReplanScope,
    pub invalidated_contract_ids: Vec<String>,
    pub affected_task_ids: Vec<String>,
    pub unchanged_task_ids: Vec<String>,
    pub changed_task_ids: Vec<String>,
    pub added_task_ids: Vec<String>,
    pub removed_task_ids: Vec<String>,
}

impl PlanRevisionDiff {
    /// Computes a deterministic adjacent-revision diff and rejects changes outside
    /// the Controller-authorized smallest scope.
    ///
    /// # Errors
    /// Returns a stable validation message when the revisions are not adjacent,
    /// plan identity changes, an unaffected task changes, or the declared affected
    /// set is not actually superseded.
    pub fn between(
        previous: &Value,
        next: &Value,
        scope: ReplanScope,
        invalidated_contract_ids: &[String],
        affected_task_ids: &[String],
    ) -> Result<Self, String> {
        let previous_plan_id = string_at(previous, "/plan_id")?;
        let next_plan_id = string_at(next, "/plan_id")?;
        if previous_plan_id != next_plan_id {
            return Err("superseding revision must preserve plan_id".to_owned());
        }
        let from_revision = u32_at(previous, "/revision")?;
        let to_revision = u32_at(next, "/revision")?;
        if to_revision != from_revision.saturating_add(1)
            || next.get("supersedes_revision").and_then(Value::as_u64)
                != Some(u64::from(from_revision))
        {
            return Err("superseding revision must be immutable N+1 directly over N".to_owned());
        }

        let previous_tasks = task_map(previous)?;
        let next_tasks = task_map(next)?;
        let affected = affected_task_ids.iter().cloned().collect::<BTreeSet<_>>();
        if affected.is_empty() {
            return Err("replan requires a non-empty affected task set".to_owned());
        }

        let mut unchanged = Vec::new();
        let mut changed = Vec::new();
        let mut removed = Vec::new();
        for (task_id, old_task) in &previous_tasks {
            match next_tasks.get(task_id) {
                Some(new_task) if *new_task == *old_task => unchanged.push(task_id.clone()),
                Some(_) => {
                    if !affected.contains(task_id) {
                        return Err(format!(
                            "smallest-scope replan changed unaffected task {task_id}"
                        ));
                    }
                    changed.push(task_id.clone());
                }
                None => {
                    if !affected.contains(task_id) {
                        return Err(format!(
                            "smallest-scope replan removed unaffected task {task_id}"
                        ));
                    }
                    removed.push(task_id.clone());
                }
            }
        }
        let added = next_tasks
            .keys()
            .filter(|task_id| !previous_tasks.contains_key(*task_id))
            .cloned()
            .collect::<Vec<_>>();

        let changed_or_removed = changed
            .iter()
            .chain(&removed)
            .cloned()
            .collect::<BTreeSet<_>>();
        if !affected.is_subset(&changed_or_removed) {
            let missing = affected
                .difference(&changed_or_removed)
                .cloned()
                .collect::<Vec<_>>();
            return Err(format!(
                "replan underscopes invalidated branch; affected tasks unchanged: {}",
                missing.join(",")
            ));
        }
        validate_added_tasks_within_scope(scope, &next_tasks, &changed, &added)?;

        let mut invalidated = invalidated_contract_ids.to_vec();
        invalidated.sort();
        invalidated.dedup();
        let mut affected_sorted = affected_task_ids.to_vec();
        affected_sorted.sort();
        affected_sorted.dedup();
        Ok(Self {
            plan_id: previous_plan_id.to_owned(),
            from_revision,
            to_revision,
            from_plan_digest: digest_json(previous)?,
            to_plan_digest: digest_json(next)?,
            scope,
            invalidated_contract_ids: invalidated,
            affected_task_ids: affected_sorted,
            unchanged_task_ids: unchanged,
            changed_task_ids: changed,
            added_task_ids: added,
            removed_task_ids: removed,
        })
    }
}

fn validate_added_tasks_within_scope(
    scope: ReplanScope,
    next_tasks: &BTreeMap<String, &Value>,
    changed: &[String],
    added: &[String],
) -> Result<(), String> {
    if added.is_empty() || scope == ReplanScope::Plan {
        return Ok(());
    }
    if scope == ReplanScope::Task {
        return Err("task-scope replan cannot add new tasks".to_owned());
    }
    if changed.is_empty() {
        return Err(
            "dependency-branch additions require a retained changed task to anchor the superseded branch"
                .to_owned(),
        );
    }

    let branch_members = changed
        .iter()
        .chain(added)
        .cloned()
        .collect::<BTreeSet<_>>();
    let mut adjacency = BTreeMap::<String, BTreeSet<String>>::new();
    for (task_id, task) in next_tasks {
        for dependency in task
            .get("dependencies")
            .and_then(Value::as_array)
            .ok_or_else(|| format!("task {task_id} lacks dependencies[]"))?
        {
            let dependency = dependency
                .as_str()
                .ok_or_else(|| format!("task {task_id} dependency is not a string"))?;
            if !next_tasks.contains_key(dependency) {
                return Err(format!(
                    "task {task_id} depends on unknown task {dependency}"
                ));
            }
            if !branch_members.contains(task_id) || !branch_members.contains(dependency) {
                continue;
            }
            adjacency
                .entry(task_id.clone())
                .or_default()
                .insert(dependency.to_owned());
            adjacency
                .entry(dependency.to_owned())
                .or_default()
                .insert(task_id.clone());
        }
    }
    let mut reachable = changed.iter().cloned().collect::<BTreeSet<_>>();
    let mut queue = changed.iter().cloned().collect::<VecDeque<_>>();
    while let Some(task_id) = queue.pop_front() {
        for neighbor in adjacency.get(&task_id).into_iter().flatten() {
            if reachable.insert(neighbor.clone()) {
                queue.push_back(neighbor.clone());
            }
        }
    }
    let outside = added
        .iter()
        .filter(|task_id| !reachable.contains(*task_id))
        .cloned()
        .collect::<Vec<_>>();
    if outside.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "dependency-branch replan added tasks outside the affected branch: {}",
            outside.join(",")
        ))
    }
}

/// Computes the deterministic minimum affected set from the sole hard
/// `dependencies[]` DAG.
///
/// # Errors
/// Returns a stable validation message when the owner task is unknown or the
/// canonical dependency graph is malformed.
pub fn smallest_replan_scope_tasks(
    plan: &Value,
    owner_task_id: &str,
    scope: ReplanScope,
) -> Result<Vec<String>, String> {
    let tasks = task_map(plan)?;
    if !tasks.contains_key(owner_task_id) {
        return Err(format!("unknown invalidated task {owner_task_id}"));
    }
    if scope == ReplanScope::Plan {
        return Ok(tasks.keys().cloned().collect());
    }
    if scope == ReplanScope::Task {
        return Ok(vec![owner_task_id.to_owned()]);
    }

    let mut outgoing = BTreeMap::<String, BTreeSet<String>>::new();
    for (task_id, task) in &tasks {
        let dependencies = task
            .get("dependencies")
            .and_then(Value::as_array)
            .ok_or_else(|| format!("task {task_id} lacks dependencies[]"))?;
        for dependency in dependencies {
            let dependency = dependency
                .as_str()
                .ok_or_else(|| format!("task {task_id} dependency is not a string"))?;
            if !tasks.contains_key(dependency) {
                return Err(format!(
                    "task {task_id} depends on unknown task {dependency}"
                ));
            }
            outgoing
                .entry(dependency.to_owned())
                .or_default()
                .insert(task_id.clone());
        }
    }
    let mut affected = BTreeSet::from([owner_task_id.to_owned()]);
    let mut queue = VecDeque::from([owner_task_id.to_owned()]);
    while let Some(task_id) = queue.pop_front() {
        for dependent in outgoing.get(&task_id).into_iter().flatten() {
            if affected.insert(dependent.clone()) {
                queue.push_back(dependent.clone());
            }
        }
    }
    Ok(affected.into_iter().collect())
}

fn task_map(document: &Value) -> Result<BTreeMap<String, &Value>, String> {
    let tasks = document
        .get("tasks")
        .and_then(Value::as_array)
        .ok_or_else(|| "plan lacks tasks[]".to_owned())?;
    let mut result = BTreeMap::new();
    for task in tasks {
        let task_id = task
            .get("task_id")
            .and_then(Value::as_str)
            .ok_or_else(|| "plan task lacks task_id".to_owned())?;
        if result.insert(task_id.to_owned(), task).is_some() {
            return Err(format!("duplicate task_id {task_id}"));
        }
    }
    Ok(result)
}

fn string_at<'a>(value: &'a Value, pointer: &str) -> Result<&'a str, String> {
    value
        .pointer(pointer)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("missing string {pointer}"))
}

fn u32_at(value: &Value, pointer: &str) -> Result<u32, String> {
    value
        .pointer(pointer)
        .and_then(Value::as_u64)
        .and_then(|value| u32::try_from(value).ok())
        .ok_or_else(|| format!("missing u32 {pointer}"))
}

fn digest_json(value: &Value) -> Result<String, String> {
    let bytes =
        serde_json::to_vec(&canonicalize(value.clone())).map_err(|error| error.to_string())?;
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    Ok(format!("sha256:{:x}", hasher.finalize()))
}

fn canonicalize(value: Value) -> Value {
    match value {
        Value::Array(values) => Value::Array(values.into_iter().map(canonicalize).collect()),
        Value::Object(values) => {
            let sorted = values
                .into_iter()
                .map(|(key, value)| (key, canonicalize(value)))
                .collect::<BTreeMap<_, _>>();
            Value::Object(sorted.into_iter().collect())
        }
        scalar => scalar,
    }
}
