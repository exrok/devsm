use std::path::Path;

use bumpalo::Bump;

use super::*;

pub fn local_path(config_path: &Path) -> PathBuf {
    config_path.with_file_name("devsm.local.toml")
}

/// Resolve once per load. Values are owned by the same arena as the configuration.
pub fn load_local_options<'a>(
    config_path: &Path,
    workspace: &mut WorkspaceConfig<'a>,
    bump: &'a Bump,
) -> Result<Vec<String>, ConfigError> {
    let path = local_path(config_path);
    let content = match std::fs::read_to_string(&path) {
        Ok(content) => Some(content),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(ConfigError { message: format!("Failed to read {}: {error}", path.display()) }),
    };
    resolve_local_options(config_path, workspace, bump, content.as_deref())
}

pub fn resolve_local_options<'a>(
    config_path: &Path,
    workspace: &mut WorkspaceConfig<'a>,
    bump: &'a Bump,
    content: Option<&str>,
) -> Result<Vec<String>, ConfigError> {
    let mut values = Vec::new();
    let mut warnings = Vec::new();
    if let Some(content) = content {
        let arena = toml_spanner::Arena::new();
        let mut doc = toml_spanner::parse_recoverable(content, &arena);
        let (ctx, root) = doc.split();
        for (key, item) in root {
            if key.name != "option" {
                ctx.report_unexpected_key(0, item, key.span);
                continue;
            }
            let Ok(table) = item.require_table(ctx) else { continue };
            for (key, item) in table {
                let Some((name, declaration)) = workspace.options.iter().find(|(name, _)| *name == key.name) else {
                    let diagnostic = crate::diagnostic::Diagnostic::warning()
                        .with_message(format!("unknown option '{}' (ignored)", key.name))
                        .with_labels(vec![crate::diagnostic::DiagnosticLabel::primary(key.span.range())]);
                    warnings.push(format_config_error(
                        &local_path(config_path).display().to_string(),
                        content,
                        &diagnostic,
                    ));
                    continue;
                };
                let Ok(value) = item.require_string(ctx) else { continue };
                if !declaration.choices.contains(&value) {
                    ctx.report_custom_error(
                        format!(
                            "invalid value '{value}' for option '{name}'; choices: {}. {}",
                            declaration.choices.join(", "),
                            declaration.info
                        ),
                        item,
                    );
                    continue;
                }
                values.push((*name, &*bump.alloc_str(value)));
            }
        }
        doc.compute_error_paths();
        if doc.has_errors() {
            let file_name = local_path(config_path).display().to_string();
            let message = doc
                .errors()
                .iter()
                .map(|error| format_config_error(&file_name, content, &toml_error_to_diagnostic(error, content)))
                .collect::<String>();
            return Err(ConfigError { message });
        }
    }
    for (name, declaration) in workspace.options {
        if values.iter().any(|(n, _)| n == name) {
            continue;
        }
        let Some(value) = declaration.default else {
            return Err(ConfigError {
                message: format!(
                    "{}: option '{name}' has no default; set it in {}",
                    config_path.display(),
                    local_path(config_path).display(),
                ),
            });
        };
        values.push((*name, value));
    }
    values.sort_unstable_by_key(|(name, _)| *name);
    workspace.option_values = bump.alloc_slice_copy(&values);
    Ok(warnings)
}

pub fn emit_warnings(warnings: &[String]) {
    for warning in warnings {
        eprint!("{warning}");
        kvlog::warn!("Local configuration warning", warning = warning.as_str());
    }
}

pub(super) fn referenced_option_values<'a>(names: &[&str], values: OptionValues<'a>) -> Vec<(&'a str, &'a str)> {
    names.iter().filter_map(|name| values.iter().find(|(n, _)| n == name).copied()).collect()
}

impl<'a> Predicate<'a> {
    fn visit_options(&self, f: &mut impl FnMut(&'a str, &'a str)) {
        if let Self::Option { name, value } = self {
            f(name, value);
        }
    }
}

pub(super) trait VisitOptions<'a> {
    fn visit_option_predicates(&self, f: &mut impl FnMut(&'a str, &'a str));
}

impl<'a, T: VisitOptions<'a>> VisitOptions<'a> for If<'a, T> {
    fn visit_option_predicates(&self, f: &mut impl FnMut(&'a str, &'a str)) {
        self.cond.visit_options(f);
        self.then.visit_option_predicates(f);
        if let Some(other) = &self.or_else {
            other.visit_option_predicates(f);
        }
    }
}

impl<'a> VisitOptions<'a> for StringExpr<'a> {
    fn visit_option_predicates(&self, f: &mut impl FnMut(&'a str, &'a str)) {
        if let Self::If(branch) = self {
            branch.visit_option_predicates(f);
        }
    }
}

impl<'a> VisitOptions<'a> for StringListExpr<'a> {
    fn visit_option_predicates(&self, f: &mut impl FnMut(&'a str, &'a str)) {
        match self {
            Self::If(branch) => branch.visit_option_predicates(f),
            Self::List(items) => {
                for item in *items {
                    item.visit_option_predicates(f);
                }
            }
            _ => {}
        }
    }
}

impl<'a> VisitOptions<'a> for CommandExpr<'a> {
    fn visit_option_predicates(&self, f: &mut impl FnMut(&'a str, &'a str)) {
        match self {
            Self::Cmd(expr) => expr.visit_option_predicates(f),
            Self::Sh(expr) => expr.visit_option_predicates(f),
        }
    }
}

impl<'a> VisitOptions<'a> for RequirementListExpr<'a> {
    fn visit_option_predicates(&self, f: &mut impl FnMut(&'a str, &'a str)) {
        for item in self.items {
            if let RequirementExpr::If(branch) = item {
                branch.visit_option_predicates(f);
            }
        }
    }
}

impl<'a> VisitOptions<'a> for ReadyExpr<'a> {
    fn visit_option_predicates(&self, f: &mut impl FnMut(&'a str, &'a str)) {
        match self {
            Self::If(branch) => branch.visit_option_predicates(f),
            Self::OutputContains { pattern, .. } => pattern.visit_option_predicates(f),
        }
    }
}

impl<'a> VisitOptions<'a> for TaskConfigExpr<'a> {
    fn visit_option_predicates(&self, f: &mut impl FnMut(&'a str, &'a str)) {
        self.pwd.visit_option_predicates(f);
        self.command.visit_option_predicates(f);
        for (_, value) in self.envvar {
            value.visit_option_predicates(f);
        }
        RequirementListExpr { items: self.require }.visit_option_predicates(f);
        if let Some(ready) = &self.ready {
            ready.visit_option_predicates(f);
        }
    }
}

impl<'a> VisitOptions<'a> for TestConfigExpr<'a> {
    fn visit_option_predicates(&self, f: &mut impl FnMut(&'a str, &'a str)) {
        self.pwd.visit_option_predicates(f);
        self.command.visit_option_predicates(f);
        for (_, value) in self.envvar {
            value.visit_option_predicates(f);
        }
        RequirementListExpr { items: self.require }.visit_option_predicates(f);
    }
}

impl<'a> BumpEval<'a> for ReadyExpr<'static> {
    type Object = Option<ReadyConfig<'a>>;

    fn bump_eval(&self, env: &Environment, bump: &'a Bump) -> Result<Self::Object, EvalError> {
        match self {
            Self::If(branch) => match branch.bump_eval(env, bump) {
                Err(EvalError::EmptyBranch) => Ok(None),
                result => result,
            },
            Self::OutputContains { pattern, timeout } => match pattern.bump_eval(env, bump) {
                Ok(pattern) => {
                    Ok(Some(ReadyConfig { when: ReadyPredicate::OutputContains(pattern), timeout: *timeout }))
                }
                Err(EvalError::EmptyBranch) => Ok(None),
                Err(error) => Err(error),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONFIG: &str = r#"
[option.infra]
choices = ["docker", "native"]
default = "docker"
info = "native needs postgres and mosquitto"
[option.unused]
choices = ["a", "b"]
default = "a"
[service.postgres]
cmd = { if.option.infra = "docker", then = ["docker", { if.profile = "debug", then = "--debug" }], else = ["postgres", { var = "args" }] }
pwd = { if.option.infra = "docker", then = "./docker", else = "./native" }
env.DOCKER_ONLY = { if.option.infra = "docker", then = "1" }
env.BACKEND = { if.option.infra = "docker", then = "container", else = "host" }
require = { if.option.infra = "docker", then = ["image"], else = ["initdb"] }
ready = { if.option.infra = "native", then = { when.output_contains = "ready" } }
[test.setup]
sh = { if.option.infra = "docker", then = "docker exec pg psql", else = "psql" }
cache = {}
"#;

    #[test]
    fn options_evaluate_commands_requirements_env_pwd_and_ready() {
        let path = Path::new("/nonexistent-devsm-options-test/devsm.toml");
        let mut workspace = load_workspace_config_capturing(path, CONFIG).unwrap();
        let task = &workspace.tasks[0].1;
        let eval = |values| {
            task.eval(&Environment {
                profile: "debug",
                param: jsony_value::ValueMap::new(),
                vars: &[],
                options: values,
            })
            .unwrap()
        };
        let docker = eval(workspace.option_values);
        assert_eq!(docker.config().command, Command::Cmd(&["docker", "--debug"]));
        assert_eq!(docker.config().pwd, "./docker");
        assert!(docker.config().envvar.contains(&("DOCKER_ONLY", "1")));
        assert!(docker.config().ready.is_none());
        assert!(matches!(&docker.config().require[0], Requirement::Task(call) if &*call.name == "image"));
        assert_eq!(task.referenced_options, &["infra"]);
        assert_eq!(docker.config().option_values, &[("infra", "docker")]);
        let bump = Box::leak(Box::new(Bump::new()));
        resolve_local_options(path, &mut workspace, bump, Some("[option]\ninfra = 'native'\n")).unwrap();
        let native = eval(workspace.option_values);
        assert_eq!(native.config().command, Command::Cmd(&["postgres"]));
        assert_eq!(native.config().pwd, "./native");
        assert_eq!(native.config().envvar, &[("BACKEND", "host")]);
        assert!(matches!(native.config().ready.as_ref().unwrap().when, ReadyPredicate::OutputContains("ready")));
        assert!(matches!(&native.config().require[0], Requirement::Task(call) if &*call.name == "initdb"));
        let test = workspace.tests[0].1.to_task_config_expr();
        assert_eq!(test.referenced_options, &["infra"]);
        let evaluated = test
            .eval(&Environment {
                profile: "",
                param: jsony_value::ValueMap::new(),
                vars: &[],
                options: workspace.option_values,
            })
            .unwrap();
        assert_eq!(evaluated.config().command, Command::Sh { script: "psql", args: &[] });
        // Previously evaluated jobs retain their original values.
        assert_eq!(docker.config().option_values, &[("infra", "docker")]);
    }

    #[test]
    fn local_options_are_strict_except_for_unknown_option_names() {
        let path = Path::new("/nonexistent-devsm-options-test/devsm.toml");
        let mut workspace = load_workspace_config_capturing(path, CONFIG).unwrap();
        let bump = Box::leak(Box::new(Bump::new()));
        let warnings = resolve_local_options(
            path,
            &mut workspace,
            bump,
            Some("[option]\nold_branch = 'gone'\ninfra = 'native'\n"),
        )
        .unwrap();
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("unknown option 'old_branch'"));
        for invalid in ["[option", "[service.pg]\ncmd = 'bad'", "[option]\ninfra = 'typo'", "[option]\ninfra = 1"] {
            let error = resolve_local_options(path, &mut workspace, bump, Some(invalid)).unwrap_err();
            assert!(error.message.contains("devsm.local.toml"), "{error}");
        }
        resolve_local_options(path, &mut workspace, bump, None).unwrap();
        assert_eq!(workspace.option_values, &[("infra", "docker"), ("unused", "a")]);
    }

    #[test]
    fn options_without_defaults_require_a_local_choice() {
        let path = Path::new("/nonexistent-devsm-options-test/devsm.toml");
        let arena = toml_spanner::Arena::new();
        let bump = Bump::new();
        let mut doc = toml_spanner::parse_recoverable("[option.infra]\nchoices = ['docker', 'native']", &arena);
        let mut workspace = toml_handler::parse_workspace(path.parent().unwrap(), &bump, &mut doc).unwrap();
        let error = resolve_local_options(path, &mut workspace, &bump, None).unwrap_err();
        assert!(error.message.contains("option 'infra' has no default"));
        resolve_local_options(path, &mut workspace, &bump, Some("[option]\ninfra = 'native'")).unwrap();
        assert_eq!(workspace.option_values, &[("infra", "native")]);
    }

    #[test]
    fn options_are_fixed_for_each_config_generation() {
        let path = Path::new("/nonexistent-devsm-options-test/devsm.toml");
        let original = load_workspace_generation_capturing(path, CONFIG.to_string()).unwrap();
        let replacement =
            load_workspace_generation_capturing(path, CONFIG.replace("default = \"docker\"", "default = \"native\""))
                .unwrap();
        let original = TaskConfigSource::from_workspace_task(original, 0);
        let replacement = TaskConfigSource::from_workspace_task(replacement, 0);
        let env = Environment {
            profile: "",
            param: jsony_value::ValueMap::new(),
            vars: &[],
            options: &[("infra", "native")],
        };
        assert_eq!(original.eval(&env).unwrap().config().option_values, &[("infra", "docker")]);
        assert_eq!(replacement.eval(&env).unwrap().config().option_values, &[("infra", "native")]);
    }
}
