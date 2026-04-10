//! Diagnostic-only sizing report for task/job allocation footprint.
//!
//! Run with: `cargo test alloc_report_restart_footprint -- --ignored --nocapture`

use crate::config::{
    Environment, TaskConfig, TaskConfigExpr, TaskConfigRc, WorkspaceConfig, load_workspace_config_capturing,
};
use crate::workspace::{BaseTask, Job, JobIndex, JobIndexList, JobStatus};
use bumpalo::Bump;
use jsony_value::{Value, ValueMap, ValueString};
use std::{collections::BTreeMap, mem::size_of, path::PathBuf};

#[derive(Debug, Clone)]
struct ScenarioMeasurement {
    name: String,
    profile: String,
    bump_bytes: usize,
    shared_eval_bytes: usize,
    current_per_job_bytes: usize,
    repeated_per_job_bytes: usize,
}

fn manifest_path(relative: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(relative)
}

fn load_workspace_config_for_report(relative: &str) -> WorkspaceConfig<'static> {
    let path = manifest_path(relative);
    let content = std::fs::read_to_string(&path).unwrap();
    let content: &'static str = Box::leak(content.into_boxed_str());
    load_workspace_config_capturing(&path, content).unwrap()
}

fn base_restart_params(expr: &'static TaskConfigExpr<'static>) -> Option<ValueMap<'static>> {
    let mut params = ValueMap::new();
    for var_name in expr.collect_variables() {
        let default = expr
            .vars
            .iter()
            .find_map(|(candidate, meta)| (*candidate == var_name).then_some(meta.default))
            .flatten();
        let Some(value) = default else {
            return None;
        };
        params.insert(ValueString::from_static(var_name), Value::from(value));
    }
    Some(params)
}

fn predicted_cache_key_bytes(task: &TaskConfig<'_>, profile: &str, params: &ValueMap<'_>) -> usize {
    let Some(cache) = task.cache.as_ref() else {
        return 0;
    };
    if cache.key.is_empty() && profile.is_empty() && params.entries().is_empty() {
        return 0;
    }
    64
}

fn repeated_job_inline_bytes() -> usize {
    size_of::<Job>() + 2 * size_of::<JobIndex>()
}

fn measure_restart_scenario(
    name: String,
    expr: &'static TaskConfigExpr<'static>,
    profile: &str,
) -> Option<ScenarioMeasurement> {
    let params = base_restart_params(expr)?;
    let task = expr.eval(&Environment { profile, param: params.clone(), vars: expr.vars }).unwrap();
    let bump_bytes = task.allocated_bytes_including_metadata();
    let shared_eval_bytes = size_of::<(TaskConfig<'static>, Bump)>() + 2 * size_of::<usize>() + bump_bytes;
    let repeated_per_job_bytes =
        repeated_job_inline_bytes() + predicted_cache_key_bytes(task.config(), profile, &params);
    let current_per_job_bytes = repeated_per_job_bytes + shared_eval_bytes + profile.len();
    Some(ScenarioMeasurement {
        name,
        profile: profile.to_string(),
        bump_bytes,
        shared_eval_bytes,
        current_per_job_bytes,
        repeated_per_job_bytes,
    })
}

fn collect_restart_measurements(relative: &str) -> Vec<ScenarioMeasurement> {
    let config = load_workspace_config_for_report(relative);
    let mut measurements = Vec::new();
    for (name, expr) in config.tasks {
        let profile = expr.profiles.first().copied().unwrap_or("");
        if let Some(measurement) = measure_restart_scenario((*name).to_string(), expr, profile) {
            measurements.push(measurement);
        }
    }
    for (base_name, variants) in config.tests {
        for (variant_index, test) in variants.iter().enumerate() {
            let name = if variants.len() == 1 {
                format!("~test/{base_name}")
            } else {
                format!("~test/{base_name}.{variant_index}")
            };
            if let Some(measurement) = measure_restart_scenario(name, test.to_task_config_expr(), "") {
                measurements.push(measurement);
            }
        }
    }
    measurements
}

fn summarize(values: &[usize]) -> (usize, usize, usize, usize) {
    let mut sorted = values.to_vec();
    sorted.sort_unstable();
    let total = sorted.iter().sum::<usize>();
    let avg = total / sorted.len();
    let median = sorted[sorted.len() / 2];
    let min = sorted[0];
    let max = sorted[sorted.len() - 1];
    (avg, median, min, max)
}

fn budget_count(bytes_per_job: usize, growth_num: usize, growth_den: usize) -> usize {
    const BUDGET_BYTES: usize = 2 * 1024 * 1024;
    let adjusted = (bytes_per_job * growth_num).div_ceil(growth_den);
    BUDGET_BYTES / adjusted
}

fn print_report(relative: &str, measurements: &[ScenarioMeasurement]) {
    let current: Vec<_> = measurements.iter().map(|m| m.current_per_job_bytes).collect();
    let repeated: Vec<_> = measurements.iter().map(|m| m.repeated_per_job_bytes).collect();
    let shared_eval: Vec<_> = measurements.iter().map(|m| m.shared_eval_bytes).collect();
    let bump_bytes: Vec<_> = measurements.iter().map(|m| m.bump_bytes).collect();
    let (current_avg, current_median, current_min, current_max) = summarize(&current);
    let (repeated_avg, repeated_median, repeated_min, repeated_max) = summarize(&repeated);
    let (shared_avg, shared_median, shared_min, shared_max) = summarize(&shared_eval);
    let mut bump_distribution = BTreeMap::new();
    for bump in bump_bytes {
        *bump_distribution.entry(bump).or_insert(0usize) += 1;
    }

    println!("alloc report: {relative}");
    println!("  restart scenarios measured: {}", measurements.len());
    println!("  current bytes/job avg={current_avg} median={current_median} min={current_min} max={current_max}");
    println!("  repeated bytes/job avg={repeated_avg} median={repeated_median} min={repeated_min} max={repeated_max}");
    println!("  shared eval bytes avg={shared_avg} median={shared_median} min={shared_min} max={shared_max}");
    println!("  bump bytes distribution: {bump_distribution:?}");
    println!(
        "  2 MiB budget current jobs: ideal={} reserve1.5x={} reserve2x={}",
        budget_count(current_median, 1, 1),
        budget_count(current_median, 3, 2),
        budget_count(current_median, 2, 1),
    );
    println!(
        "  2 MiB budget repeated jobs: ideal={} reserve1.5x={} reserve2x={}",
        budget_count(repeated_median, 1, 1),
        budget_count(repeated_median, 3, 2),
        budget_count(repeated_median, 2, 1),
    );

    let mut heaviest = measurements.to_vec();
    heaviest.sort_by_key(|measurement| std::cmp::Reverse(measurement.current_per_job_bytes));
    for measurement in heaviest.into_iter().take(5) {
        println!(
            "  heavy scenario: {} profile='{}' current={} repeated={} bump={}",
            measurement.name,
            measurement.profile,
            measurement.current_per_job_bytes,
            measurement.repeated_per_job_bytes,
            measurement.bump_bytes,
        );
    }
}

#[test]
#[ignore = "diagnostic sizing output for docs/alloc.md"]
fn alloc_report_restart_footprint() {
    println!("layout sizes");
    println!("  size_of::<Job>() = {}", size_of::<Job>());
    println!("  size_of::<JobStatus>() = {}", size_of::<JobStatus>());
    println!("  size_of::<BaseTask>() = {}", size_of::<BaseTask>());
    println!("  size_of::<JobIndex>() = {}", size_of::<JobIndex>());
    println!("  size_of::<JobIndexList>() = {}", size_of::<JobIndexList>());
    println!("  size_of::<TaskConfigRc>() = {}", size_of::<TaskConfigRc>());
    println!("  size_of::<TaskConfig<'static>>() = {}", size_of::<TaskConfig<'static>>());
    println!("  size_of::<(TaskConfig<'static>, Bump)>() = {}", size_of::<(TaskConfig<'static>, Bump)>());
    println!("  size_of::<Bump>() = {}", size_of::<Bump>());
    println!("  size_of::<String>() = {}", size_of::<String>());
    println!("  size_of::<ValueMap<'static>>() = {}", size_of::<ValueMap<'static>>());
    println!("  size_of::<ValueString<'static>>() = {}", size_of::<ValueString<'static>>());
    println!("  size_of::<Value>() = {}", size_of::<Value>());
    println!(
        "  size_of::<(ValueString<'static>, Value<'static>)>() = {}",
        size_of::<(ValueString<'static>, Value<'static>)>()
    );

    let repo_measurements = collect_restart_measurements("devsm.toml");
    assert!(!repo_measurements.is_empty());
    print_report("devsm.toml", &repo_measurements);

    let big_measurements = collect_restart_measurements("schema/devsm.example-big.toml");
    assert!(!big_measurements.is_empty());
    print_report("schema/devsm.example-big.toml", &big_measurements);
}
