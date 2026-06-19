use anyhow::{Context, bail};
use jsony_value::{Value, ValueMap};
use std::borrow::Cow;

struct ArgParser<'a> {
    args: std::slice::Iter<'a, String>,
    value: Option<&'a str>,
}

/// Parses a flag value as a JSON literal, falling back to a string on failure.
///
/// # Examples
///
/// ```
/// let value = parse_flag_value("500");
/// assert!(matches!(value.as_ref(), jsony_value::ValueRef::Number(_)));
///
/// let value = parse_flag_value("true");
/// assert!(matches!(value.as_ref(), jsony_value::ValueRef::Boolean(true)));
///
/// let value = parse_flag_value("hello");
/// assert!(matches!(value.as_ref(), jsony_value::ValueRef::String(s) if s == "hello"));
/// ```
pub fn parse_flag_value(value: &str) -> Value<'_> {
    let Ok(parsed) = jsony::from_json::<Value>(value) else {
        return value.into();
    };
    parsed
}

#[derive(Debug)]
pub enum Component<'a> {
    Flags(&'a str),
    Long(&'a str),
    Value(&'a str),
    Term(&'a str),
}

impl<'a> ArgParser<'a> {
    fn new(args: &'a [String]) -> ArgParser<'a> {
        ArgParser { args: args.iter(), value: None }
    }

    fn rest(&self) -> &'a [String] {
        debug_assert!(self.value.is_none());
        self.args.as_slice()
    }

    fn next_value(&mut self) -> Option<&'a str> {
        match self.next()? {
            Component::Value(v) | Component::Term(v) => Some(v),
            _ => None,
        }
    }
}

impl<'a> Iterator for ArgParser<'a> {
    type Item = Component<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(value) = self.value.take() {
            return Some(Component::Value(value));
        }
        let arg = self.args.next()?;

        if let Some(long_or_pair) = arg.strip_prefix("--") {
            if let Some((long, value)) = long_or_pair.split_once("=") {
                self.value = Some(value);
                return Some(Component::Long(long));
            }
            return Some(Component::Long(long_or_pair));
        }

        if let Some(flags) = arg.strip_prefix("-") {
            return Some(Component::Flags(flags));
        }

        Some(Component::Term(arg))
    }
}

fn is_help(component: &Component<'_>) -> bool {
    matches!(component, Component::Long("help") | Component::Flags("h"))
}

fn parse_no_args<'a>(
    parser: &mut ArgParser<'a>,
    command: Command<'a>,
    topic: HelpTopic,
    command_name: &str,
) -> anyhow::Result<Command<'a>> {
    for component in parser.by_ref() {
        if is_help(&component) {
            return Ok(Command::Help(topic));
        }
        match component {
            Component::Term(arg) => bail!("Unexpected argument in {command_name} command: {:?}", arg),
            Component::Long(long) => bail!("Unknown flag --{} in {command_name} command", long),
            Component::Flags(flags) => {
                if let Some(flag) = flags.chars().next() {
                    bail!("Unknown flag -{} in {command_name} command", flag);
                }
            }
            Component::Value(val) => bail!("Unexpected value: {:?}", val),
        }
    }
    Ok(command)
}

pub struct GlobalArguments<'a> {
    pub from: Option<&'a str>,
}

pub enum Command<'a> {
    Help(HelpTopic),
    Tui,
    Global,
    Server,
    RestartSelected,
    Start { job: &'a str, value_map: ValueMap<'a>, as_test: bool, cached: bool },
    Restart { job: &'a str, value_map: ValueMap<'a>, as_test: bool, cached: bool },
    Exec { job: &'a str, value_map: ValueMap<'a>, trailing_args: &'a [String] },
    Run { job: &'a str, value_map: ValueMap<'a>, trailing_args: &'a [String], as_test: bool, derive_cache_key: bool },
    Auto { job: &'a str, value_map: ValueMap<'a>, trailing_args: &'a [String] },
    Stop { job: &'a str },
    Status { name: Option<&'a str> },
    Test { filters: Vec<TestFilter<'a>>, force: bool },
    RerunTests { only_failed: bool },
    Validate { path: Option<&'a str>, skip_path_checks: bool },
    Get { resource: GetResource },
    FunctionCall { name: &'a str },
    Logs { options: LogsOptions<'a> },
    Complete { context: CompleteContext<'a> },
    Completions { shell: CompletionShell },
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum HelpTopic {
    General,
    Global,
    Run,
    Exec,
    Start,
    Restart,
    RestartSelected,
    Stop,
    Status,
    Test,
    RerunTests,
    Logs,
    Get,
    GetWorkspace,
    GetWorkspaceConfigPath,
    GetWorkspaces,
    GetDefaultUserConfig,
    GetLoggedRustPanics,
    Function,
    FunctionCall,
    Completions,
    SelfCommand,
    SelfServer,
    SelfValidate,
    SelfLogs,
    SelfComplete,
}

#[derive(Copy, Clone, Debug)]
pub enum CompletionShell {
    Bash,
    Fish,
    Zsh,
}

#[derive(Debug, Clone)]
pub enum CompleteContext<'a> {
    Commands,
    Tasks,
    Tests,
    Profiles { task: &'a str },
    Vars { task: &'a str, exclude: Vec<&'a str> },
    ForwardPrefix { task: &'a str },
    TaskArgs { task: &'a str, exclude: Vec<&'a str>, args: &'a [String] },
    Groups,
    Functions,
    Tags,
    GetResources,
    Kinds,
    Runnables,
}

#[derive(Debug, Default)]
pub struct LogsOptions<'a> {
    pub max_age: Option<&'a str>,
    pub tasks: Vec<TaskSelector<'a>>,
    pub job: Option<u32>,
    pub kinds: Vec<KindSelector<'a>>,
    pub pattern: Option<&'a str>,
    pub follow: bool,
    pub retry: bool,
    pub oldest: Option<usize>,
    pub newest: Option<usize>,
    pub without_taskname: bool,
}

#[derive(Debug, Clone)]
pub struct TaskSelector<'a> {
    pub name: &'a str,
    pub latest: bool,
}

#[derive(Debug, Clone)]
pub struct KindSelector<'a> {
    pub kind: &'a str,
    pub latest: bool,
}

pub enum GetResource {
    SelfLogs { follow: bool },
    WorkspaceConfigPath,
    DefaultUserConfig,
    LoggedRustPanics,
    Workspaces { json: bool },
}

/// Filter for test selection.
/// - `+tag`: Include tests with this tag (OR combined with other includes)
/// - `-tag`: Exclude tests with this tag (absolute exclusion, applied first)
/// - `name`: Include tests with this name (OR combined with other includes)
#[derive(Debug, Clone)]
pub enum TestFilter<'a> {
    IncludeTag(Cow<'a, str>),
    ExcludeTag(Cow<'a, str>),
    IncludeName(Cow<'a, str>),
}

fn parse_param_components<'a>(parser: &mut ArgParser<'a>) -> anyhow::Result<ValueMap<'a>> {
    let mut value_map = ValueMap::new();
    while let Some(component) = parser.next() {
        match component {
            Component::Long(key) => {
                let Some(val) = parser.next_value() else {
                    bail!("Flag --{} requires a value (use --{}=value)", key, key);
                };
                value_map.insert(key.into(), parse_flag_value(val));
            }
            Component::Term(json) => {
                let parsed: ValueMap = jsony::from_json(json).context("Parsing job parameters")?;
                for (k, v) in parsed.entries() {
                    value_map.insert(k.clone(), v.clone());
                }
            }
            Component::Flags(flags) => {
                if let Some(flag) = flags.chars().next() {
                    bail!("Unknown flag -{}", flag);
                }
            }
            Component::Value(val) => {
                bail!("Unexpected value: {:?}", val);
            }
        }
    }

    Ok(value_map)
}

pub fn parse_task_params<'a>(args: &'a [String]) -> anyhow::Result<ValueMap<'a>> {
    let mut parser = ArgParser::new(args);
    parse_param_components(&mut parser)
}

pub fn parse_run_trailing_params<'a>(
    args: &'a [String],
    as_test: &mut bool,
    derive_cache_key: &mut bool,
) -> anyhow::Result<ValueMap<'a>> {
    let mut parser = ArgParser::new(args);
    let mut value_map = ValueMap::new();
    while let Some(component) = parser.next() {
        match component {
            Component::Long("as-test") => {
                *as_test = true;
            }
            Component::Long("derive-cache-key") => {
                *derive_cache_key = true;
            }
            Component::Long(key) => {
                let Some(val) = parser.next_value() else {
                    bail!("Flag --{} requires a value (use --{}=value)", key, key);
                };
                value_map.insert(key.into(), parse_flag_value(val));
            }
            Component::Term(json) => {
                let parsed: ValueMap = jsony::from_json(json).context("Parsing job parameters")?;
                for (k, v) in parsed.entries() {
                    value_map.insert(k.clone(), v.clone());
                }
            }
            Component::Flags(flags) => {
                if let Some(flag) = flags.chars().next() {
                    bail!("Unknown flag -{}", flag);
                }
            }
            Component::Value(val) => {
                bail!("Unexpected value: {:?}", val);
            }
        }
    }

    Ok(value_map)
}

fn parse_daemon_task<'a>(parser: &mut ArgParser<'a>, restart: bool) -> anyhow::Result<Command<'a>> {
    let mut as_test = false;
    let mut cached = false;
    let mut job = None;
    let mut value_map = ValueMap::new();
    let help_topic = if restart { HelpTopic::Restart } else { HelpTopic::Start };

    while let Some(component) = parser.next() {
        match component {
            Component::Long("help") => return Ok(Command::Help(help_topic)),
            Component::Long("as-test") => as_test = true,
            Component::Long("cached") => cached = true,
            Component::Long(key) => {
                let Some(val) = parser.next_value() else {
                    bail!("Flag --{} requires a value (use --{}=value)", key, key);
                };
                value_map.insert(key.into(), parse_flag_value(val));
            }
            Component::Term(arg) => {
                if job.is_none() {
                    job = Some(arg);
                } else {
                    let parsed: ValueMap = jsony::from_json(arg).context("Parsing job parameters")?;
                    for (k, v) in parsed.entries() {
                        value_map.insert(k.clone(), v.clone());
                    }
                }
            }
            Component::Flags(flags) => {
                if flags == "h" {
                    return Ok(Command::Help(help_topic));
                }
                if let Some(flag) = flags.chars().next() {
                    bail!("Unknown flag -{}", flag);
                }
            }
            Component::Value(val) => {
                bail!("Unexpected value: {:?}", val);
            }
        }
    }

    let Some(job) = job else {
        bail!("Missing name of job");
    };

    if restart {
        Ok(Command::Restart { job, value_map, as_test, cached })
    } else {
        Ok(Command::Start { job, value_map, as_test, cached })
    }
}

fn parse_exec<'a>(parser: &mut ArgParser<'a>) -> anyhow::Result<Command<'a>> {
    let job = match parser.next() {
        Some(component) if is_help(&component) => return Ok(Command::Help(HelpTopic::Exec)),
        Some(Component::Term(name)) => name,
        Some(f) => bail!("Expected name of job, found {:?}", f),
        None => bail!("Missing name of job"),
    };
    Ok(Command::Exec { job, value_map: ValueMap::new(), trailing_args: parser.rest() })
}

fn parse_run<'a>(parser: &mut ArgParser<'a>) -> anyhow::Result<Command<'a>> {
    let mut as_test = false;
    let mut derive_cache_key = false;
    let mut job = None;
    let mut value_map = ValueMap::new();

    while let Some(component) = parser.next() {
        match component {
            Component::Long("help") => return Ok(Command::Help(HelpTopic::Run)),
            Component::Long("as-test") => {
                as_test = true;
            }
            Component::Long("derive-cache-key") => {
                derive_cache_key = true;
            }
            Component::Long(key) => {
                let Some(val) = parser.next_value() else {
                    bail!("Flag --{} requires a value (use --{}=value)", key, key);
                };
                value_map.insert(key.into(), parse_flag_value(val));
            }
            Component::Term(arg) => {
                if job.is_none() {
                    job = Some(arg);
                    break;
                } else {
                    let parsed: ValueMap = jsony::from_json(arg).context("Parsing job parameters")?;
                    for (k, v) in parsed.entries() {
                        value_map.insert(k.clone(), v.clone());
                    }
                }
            }
            Component::Flags(flags) => {
                if flags == "h" {
                    return Ok(Command::Help(HelpTopic::Run));
                }
                if let Some(flag) = flags.chars().next() {
                    bail!("Unknown flag -{}", flag);
                }
            }
            Component::Value(val) => {
                bail!("Unexpected value: {:?}", val);
            }
        }
    }

    let Some(job) = job else {
        bail!("Missing name of job");
    };

    Ok(Command::Run { job, value_map, trailing_args: parser.rest(), as_test, derive_cache_key })
}

/// Parse validate command arguments.
/// - Positional argument: config file path (optional)
/// - `--skip-path-checks`: skip validation of pwd paths
fn parse_validate<'a>(parser: &mut ArgParser<'a>) -> anyhow::Result<Command<'a>> {
    let mut path = None;
    let mut skip_path_checks = false;
    for component in parser.by_ref() {
        match component {
            Component::Term(arg) => {
                if path.is_some() {
                    bail!("Unexpected argument: {:?}", arg);
                }
                path = Some(arg);
            }
            Component::Long(long) => match long {
                "help" => return Ok(Command::Help(HelpTopic::SelfValidate)),
                "skip-path-checks" => skip_path_checks = true,
                _ => bail!("Unknown flag --{} in validate command", long),
            },
            Component::Flags(flags) => {
                if flags == "h" {
                    return Ok(Command::Help(HelpTopic::SelfValidate));
                }
                if let Some(flag) = flags.chars().next() {
                    bail!("Unknown flag -{}", flag);
                }
            }
            Component::Value(val) => {
                bail!("Unexpected value: {:?}", val);
            }
        }
    }
    Ok(Command::Validate { path, skip_path_checks })
}

/// Parse test filters from remaining arguments.
/// - `+tag` includes tests with tag
/// - `-tag` excludes tests with tag
/// - `name` includes tests with name
fn parse_test_filters<'a>(parser: &mut ArgParser<'a>) -> anyhow::Result<Command<'a>> {
    let mut filters = Vec::new();
    let mut force = false;
    for component in parser.by_ref() {
        match component {
            Component::Term(arg) => {
                if let Some(tag) = arg.strip_prefix('+') {
                    filters.push(TestFilter::IncludeTag(tag.into()));
                } else if let Some(tag) = arg.strip_prefix('-') {
                    filters.push(TestFilter::ExcludeTag(tag.into()));
                } else {
                    filters.push(TestFilter::IncludeName(arg.into()));
                }
            }
            Component::Long(long) => {
                if matches!(long, "force" | "no-cache") {
                    force = true;
                } else if long == "help" {
                    return Ok(Command::Help(HelpTopic::Test));
                } else {
                    bail!("Unexpected flag --{} in test command", long);
                }
            }
            Component::Flags(flags) => {
                if flags == "h" {
                    return Ok(Command::Help(HelpTopic::Test));
                }
                // Check if this is actually a negative tag filter (e.g., -slow)
                // Single-character flags starting with a letter are treated as exclude tags
                if !flags.is_empty() && flags.chars().next().map(|c| c.is_alphabetic()).unwrap_or(false) {
                    filters.push(TestFilter::ExcludeTag(flags.into()));
                } else if let Some(flag) = flags.chars().next() {
                    bail!("Unknown flag -{}", flag);
                }
            }
            Component::Value(val) => {
                bail!("Unexpected value: {:?}", val);
            }
        }
    }
    Ok(Command::Test { filters, force })
}

fn parse_rerun_tests<'a>(parser: &mut ArgParser<'a>) -> anyhow::Result<Command<'a>> {
    let mut only_failed = false;
    for component in parser.by_ref() {
        match component {
            Component::Long("help") => return Ok(Command::Help(HelpTopic::RerunTests)),
            Component::Long("only-failed") => only_failed = true,
            Component::Long(long) => bail!("Unknown flag --{} in rerun-tests command", long),
            Component::Flags("h") => return Ok(Command::Help(HelpTopic::RerunTests)),
            Component::Flags(flags) => {
                if let Some(flag) = flags.chars().next() {
                    bail!("Unknown flag -{} in rerun-tests command", flag);
                }
            }
            Component::Term(arg) => bail!("Unexpected argument in rerun-tests command: {:?}", arg),
            Component::Value(val) => bail!("Unexpected value: {:?}", val),
        }
    }
    Ok(Command::RerunTests { only_failed })
}

fn parse_task_selector(value: &str) -> TaskSelector<'_> {
    if let Some(name) = value.strip_suffix("@latest") {
        TaskSelector { name, latest: true }
    } else {
        TaskSelector { name: value, latest: false }
    }
}

fn parse_kind_selector(value: &str) -> KindSelector<'_> {
    if let Some(kind) = value.strip_suffix("@latest") {
        KindSelector { kind, latest: true }
    } else {
        KindSelector { kind: value, latest: false }
    }
}

fn parse_complete<'a>(parser: &mut ArgParser<'a>) -> anyhow::Result<Command<'a>> {
    let mut task: Option<&'a str> = None;
    let mut context_str: Option<&'a str> = None;
    let mut exclude: Vec<&'a str> = Vec::new();
    let mut args: &'a [String] = &[];

    while let Some(component) = parser.next() {
        match component {
            Component::Term(arg) => {
                if context_str.is_some() {
                    bail!("Unexpected argument: {:?}", arg);
                }
                context_str = Some(arg);
            }
            Component::Long(long) => match long {
                "help" => return Ok(Command::Help(HelpTopic::SelfComplete)),
                "task" => {
                    let Some(val) = parser.next_value() else {
                        bail!("Flag --task requires a value (use --task=NAME)");
                    };
                    task = Some(val);
                }
                "exclude" => {
                    let Some(val) = parser.next_value() else {
                        bail!("Flag --exclude requires a value (use --exclude=var1,var2)");
                    };
                    exclude.extend(val.split(',').filter(|s| !s.is_empty()));
                }
                "" => {
                    args = parser.rest();
                    break;
                }
                _ => bail!("Unknown flag --{} in complete command", long),
            },
            Component::Flags(flags) => {
                if flags == "h" {
                    return Ok(Command::Help(HelpTopic::SelfComplete));
                }
                if let Some(flag) = flags.chars().next() {
                    bail!("Unknown flag -{}", flag);
                }
            }
            Component::Value(val) => {
                bail!("Unexpected value: {:?}", val);
            }
        }
    }

    let Some(context_str) = context_str else {
        bail!(
            "complete requires a context (commands, tasks, runnables, tests, profiles, vars, forward-prefix, task-args, groups, functions, tags, get-resources, kinds)"
        );
    };

    let context = match context_str {
        "commands" => CompleteContext::Commands,
        "tasks" => CompleteContext::Tasks,
        "runnables" => CompleteContext::Runnables,
        "tests" => CompleteContext::Tests,
        "profiles" => {
            let Some(task) = task else {
                bail!("complete profiles requires --task=NAME");
            };
            CompleteContext::Profiles { task }
        }
        "vars" => {
            let Some(task) = task else {
                bail!("complete vars requires --task=NAME");
            };
            CompleteContext::Vars { task, exclude }
        }
        "forward-prefix" => {
            let Some(task) = task else {
                bail!("complete forward-prefix requires --task=NAME");
            };
            CompleteContext::ForwardPrefix { task }
        }
        "task-args" => {
            let Some(task) = task else {
                bail!("complete task-args requires --task=NAME");
            };
            CompleteContext::TaskArgs { task, exclude, args }
        }
        "groups" => CompleteContext::Groups,
        "functions" => CompleteContext::Functions,
        "tags" => CompleteContext::Tags,
        "get-resources" => CompleteContext::GetResources,
        "kinds" => CompleteContext::Kinds,
        _ => bail!("Unknown complete context: {}", context_str),
    };

    Ok(Command::Complete { context })
}

fn parse_logs<'a>(parser: &mut ArgParser<'a>) -> anyhow::Result<Command<'a>> {
    let mut options = LogsOptions::default();

    while let Some(component) = parser.next() {
        match component {
            Component::Term(arg) => {
                if options.pattern.is_some() {
                    bail!("Only one pattern argument is allowed");
                }
                options.pattern = Some(arg);
            }
            Component::Long(long) => match long {
                "help" => return Ok(Command::Help(HelpTopic::Logs)),
                "follow" => options.follow = true,
                "retry" => options.retry = true,
                "without-taskname" => options.without_taskname = true,
                "max-age" => {
                    let Some(val) = parser.next_value() else {
                        bail!("Flag --max-age requires a value (use --max-age=5s)");
                    };
                    options.max_age = Some(val);
                }
                "task" => {
                    let Some(val) = parser.next_value() else {
                        bail!("Flag --task requires a value (use --task=NAME)");
                    };
                    options.tasks.push(parse_task_selector(val));
                }
                "job" => {
                    let Some(val) = parser.next_value() else {
                        bail!("Flag --job requires a value (use --job=INDEX)");
                    };
                    options.job = Some(val.parse().context("Invalid job index")?);
                }
                "kind" => {
                    let Some(val) = parser.next_value() else {
                        bail!("Flag --kind requires a value (use --kind=service)");
                    };
                    options.kinds.push(parse_kind_selector(val));
                }
                "oldest" => {
                    let Some(val) = parser.next_value() else {
                        bail!("Flag --oldest requires a value (use --oldest=N)");
                    };
                    options.oldest = Some(val.parse().context("Invalid oldest count")?);
                }
                "newest" => {
                    let Some(val) = parser.next_value() else {
                        bail!("Flag --newest requires a value (use --newest=N)");
                    };
                    options.newest = Some(val.parse().context("Invalid newest count")?);
                }
                _ => bail!("Unknown flag --{} in logs command", long),
            },
            Component::Flags(flags) => {
                if flags.chars().any(|flag| flag == 'h') {
                    return Ok(Command::Help(HelpTopic::Logs));
                }
                for flag in flags.chars() {
                    match flag {
                        'f' => options.follow = true,
                        _ => bail!("Unknown flag -{} in logs command", flag),
                    }
                }
            }
            Component::Value(val) => {
                bail!("Unexpected value: {:?}", val);
            }
        }
    }

    Ok(Command::Logs { options })
}

fn parse_self_logs<'a>(parser: &mut ArgParser<'a>) -> anyhow::Result<Command<'a>> {
    let mut follow = false;
    for component in parser.by_ref() {
        match component {
            Component::Flags(flags) => {
                if flags.chars().any(|flag| flag == 'h') {
                    return Ok(Command::Help(HelpTopic::SelfLogs));
                }
                for flag in flags.chars() {
                    match flag {
                        'f' => follow = true,
                        _ => bail!("Unknown flag -{} in self logs command", flag),
                    }
                }
            }
            Component::Long(long) => match long {
                "help" => return Ok(Command::Help(HelpTopic::SelfLogs)),
                "follow" => follow = true,
                _ => bail!("Unknown flag --{} in self logs command", long),
            },
            Component::Term(arg) => bail!("Unexpected argument: {:?}", arg),
            Component::Value(val) => bail!("Unexpected value: {:?}", val),
        }
    }
    Ok(Command::Get { resource: GetResource::SelfLogs { follow } })
}

fn parse_completions<'a>(parser: &mut ArgParser<'a>) -> anyhow::Result<Command<'a>> {
    let shell = match parser.next() {
        Some(component) if is_help(&component) => return Ok(Command::Help(HelpTopic::Completions)),
        Some(Component::Term(shell)) => shell,
        Some(other) => bail!("Expected shell name, found {:?}", other),
        None => bail!("completions requires a shell name (bash, fish, zsh)"),
    };
    let shell = match shell {
        "bash" => CompletionShell::Bash,
        "fish" => CompletionShell::Fish,
        "zsh" => CompletionShell::Zsh,
        _ => bail!("Unknown shell: {} (expected bash, fish, or zsh)", shell),
    };
    if let Some(extra) = parser.next() {
        if is_help(&extra) {
            return Ok(Command::Help(HelpTopic::Completions));
        }
        bail!("Unexpected argument after shell: {:?}", extra);
    }
    Ok(Command::Completions { shell })
}

fn parse_self<'a>(parser: &mut ArgParser<'a>) -> anyhow::Result<Command<'a>> {
    let subcommand = match parser.next() {
        Some(component) if is_help(&component) => return Ok(Command::Help(HelpTopic::SelfCommand)),
        Some(Component::Term(subcommand)) => subcommand,
        Some(other) => bail!("Expected self subcommand, found {:?}", other),
        None => bail!("self requires a subcommand (server, validate, logs, complete)"),
    };
    match subcommand {
        "server" => parse_no_args(parser, Command::Server, HelpTopic::SelfServer, "self server"),
        "validate" => parse_validate(parser),
        "logs" => parse_self_logs(parser),
        "complete" => parse_complete(parser),
        _ => bail!("Unknown self subcommand: {}", subcommand),
    }
}

pub fn parse<'a>(args: &'a [String]) -> anyhow::Result<(GlobalArguments<'a>, Command<'a>)> {
    let mut parser = ArgParser::new(args);
    let mut global = GlobalArguments { from: None };

    let command = 'command: loop {
        let Some(arg) = parser.next() else {
            break 'command Command::Tui;
        };
        match arg {
            Component::Flags(flags) =>
            {
                #[allow(clippy::never_loop)]
                for flag in flags.chars() {
                    match flag {
                        'h' => break 'command Command::Help(HelpTopic::General),
                        _ => bail!("Unknown flag, -{}", flag),
                    }
                }
            }
            Component::Long(long) => {
                if long == "help" {
                    break 'command Command::Help(HelpTopic::General);
                }
                if long == "from" {
                    if let Some(Component::Long(value) | Component::Value(value)) = parser.next() {
                        if global.from.is_some() {
                            bail!("from already specified")
                        }
                        global.from = Some(value);
                    } else {
                        bail!("Expected value after from");
                    }
                }
            }
            Component::Value(value) => {
                bail!("Dangling value found: {:?}", value)
            }
            Component::Term(command) => match command {
                "global" => break 'command parse_no_args(&mut parser, Command::Global, HelpTopic::Global, "global")?,
                "self" => break 'command parse_self(&mut parser)?,
                "completions" => break 'command parse_completions(&mut parser)?,
                "restart-selected" => {
                    break 'command parse_no_args(
                        &mut parser,
                        Command::RestartSelected,
                        HelpTopic::RestartSelected,
                        "restart-selected",
                    )?;
                }
                "start" => break 'command parse_daemon_task(&mut parser, false)?,
                "restart" => break 'command parse_daemon_task(&mut parser, true)?,
                "exec" => break 'command parse_exec(&mut parser)?,
                "run" => break 'command parse_run(&mut parser)?,
                "stop" => {
                    let job = match parser.next() {
                        Some(component) if is_help(&component) => break 'command Command::Help(HelpTopic::Stop),
                        Some(Component::Term(job)) => job,
                        Some(other) => bail!("Expected task name or job index, found {:?}", other),
                        None => bail!("stop requires a task name or job index"),
                    };
                    if let Some(extra) = parser.next() {
                        if is_help(&extra) {
                            break 'command Command::Help(HelpTopic::Stop);
                        }
                        bail!("Unexpected argument after task name or job index: {:?}", extra);
                    }
                    break 'command Command::Stop { job };
                }
                "status" => {
                    let mut name = None;
                    if let Some(extra) = parser.next() {
                        if is_help(&extra) {
                            break 'command Command::Help(HelpTopic::Status);
                        }
                        match extra {
                            Component::Term(arg) => name = Some(arg),
                            other => bail!("Expected task or group name, found {:?}", other),
                        }
                    }
                    if let Some(extra) = parser.next() {
                        if is_help(&extra) {
                            break 'command Command::Help(HelpTopic::Status);
                        }
                        bail!("Unexpected argument after name: {:?}", extra);
                    }
                    break 'command Command::Status { name };
                }
                "test" => break 'command parse_test_filters(&mut parser)?,
                "rerun-tests" => break 'command parse_rerun_tests(&mut parser)?,
                "logs" => break 'command parse_logs(&mut parser)?,
                "function" => {
                    let subcommand = match parser.next() {
                        Some(component) if is_help(&component) => break 'command Command::Help(HelpTopic::Function),
                        Some(Component::Term(subcommand)) => subcommand,
                        Some(other) => bail!("Expected function subcommand, found {:?}", other),
                        None => bail!("function requires a subcommand (call)"),
                    };
                    match subcommand {
                        "call" => {
                            let fn_name = match parser.next() {
                                Some(component) if is_help(&component) => {
                                    break 'command Command::Help(HelpTopic::FunctionCall);
                                }
                                Some(Component::Term(fn_name)) => fn_name,
                                Some(other) => bail!("Expected function name, found {:?}", other),
                                None => bail!("function call requires a function name"),
                            };
                            if let Some(extra) = parser.next() {
                                if is_help(&extra) {
                                    break 'command Command::Help(HelpTopic::FunctionCall);
                                }
                                bail!("Unexpected argument after function name: {:?}", extra);
                            }
                            break 'command Command::FunctionCall { name: fn_name };
                        }
                        _ => bail!("Unknown function subcommand: {}", subcommand),
                    }
                }
                "get" => {
                    let resource = match parser.next() {
                        Some(component) if is_help(&component) => break 'command Command::Help(HelpTopic::Get),
                        Some(Component::Term(resource)) => resource,
                        Some(other) => bail!("Expected resource name, found {:?}", other),
                        None => bail!("get requires a resource name"),
                    };
                    match resource {
                        "default-user-config" => {
                            break 'command parse_no_args(
                                &mut parser,
                                Command::Get { resource: GetResource::DefaultUserConfig },
                                HelpTopic::GetDefaultUserConfig,
                                "get default-user-config",
                            )?;
                        }
                        "workspace" => {
                            let sub = match parser.next() {
                                Some(component) if is_help(&component) => {
                                    break 'command Command::Help(HelpTopic::GetWorkspace);
                                }
                                Some(Component::Term(sub)) => sub,
                                Some(other) => bail!("Expected workspace resource, found {:?}", other),
                                None => bail!("get workspace requires a sub-resource"),
                            };
                            match sub {
                                "config-path" => {
                                    break 'command parse_no_args(
                                        &mut parser,
                                        Command::Get { resource: GetResource::WorkspaceConfigPath },
                                        HelpTopic::GetWorkspaceConfigPath,
                                        "get workspace config-path",
                                    )?;
                                }
                                _ => bail!("Unknown workspace resource: {}", sub),
                            }
                        }
                        "logged-rust-panics" => {
                            break 'command parse_no_args(
                                &mut parser,
                                Command::Get { resource: GetResource::LoggedRustPanics },
                                HelpTopic::GetLoggedRustPanics,
                                "get logged-rust-panics",
                            )?;
                        }
                        "workspaces" => {
                            let mut json = false;
                            for component in parser.by_ref() {
                                if is_help(&component) {
                                    break 'command Command::Help(HelpTopic::GetWorkspaces);
                                }
                                match component {
                                    Component::Long(long) => match long {
                                        "json" => json = true,
                                        _ => bail!("Unknown flag --{} in get workspaces", long),
                                    },
                                    Component::Flags(flags) => {
                                        if let Some(flag) = flags.chars().next() {
                                            bail!("Unknown flag -{} in get workspaces", flag);
                                        }
                                    }
                                    Component::Term(arg) => bail!("Unexpected argument: {:?}", arg),
                                    Component::Value(val) => bail!("Unexpected value: {:?}", val),
                                }
                            }
                            break 'command Command::Get { resource: GetResource::Workspaces { json } };
                        }
                        _ => bail!("Unknown resource: {}", resource),
                    }
                }
                job => break 'command Command::Auto { job, value_map: ValueMap::new(), trailing_args: parser.rest() },
            },
        }
    };

    Ok((global, command))
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsony_value::ValueRef;

    #[test]
    fn parse_flag_value_json_types() {
        let v = parse_flag_value("500");
        let ValueRef::Number(n) = v.as_ref() else { panic!() };
        assert_eq!(n.as_u64(), Some(500));

        let v = parse_flag_value("-42");
        let ValueRef::Number(n) = v.as_ref() else { panic!() };
        assert_eq!(n.as_i64(), Some(-42));

        let v = parse_flag_value("3.143");
        let ValueRef::Number(n) = v.as_ref() else { panic!() };
        assert_eq!(n.as_f64(), Some(3.143));

        let v = parse_flag_value("true");
        let ValueRef::Boolean(b) = v.as_ref() else { panic!() };
        assert!(*b == true);

        let v = parse_flag_value("false");
        let ValueRef::Boolean(b) = v.as_ref() else { panic!() };
        assert!(*b == false);

        assert!(matches!(parse_flag_value("null").as_ref(), ValueRef::Null(_)));

        let v = parse_flag_value("\"quoted\"");
        let ValueRef::String(s) = v.as_ref() else { panic!() };
        assert_eq!(&**s, "quoted");

        let v = parse_flag_value("[1,2,3]");
        let ValueRef::List(list) = v.as_ref() else { panic!() };
        assert_eq!(list.as_slice().len(), 3);

        let v = parse_flag_value("{\"a\":1}");
        let ValueRef::Map(map) = v.as_ref() else { panic!() };
        assert_eq!(map.entries().len(), 1);
    }

    #[test]
    fn parse_flag_value_string_fallbacks() {
        let cases = [
            ("hello", "hello"),
            ("/usr/bin/bash", "/usr/bin/bash"),
            ("https://example.com", "https://example.com"),
            ("", ""),
        ];
        for (input, expected) in cases {
            let v = parse_flag_value(input);
            let ValueRef::String(s) = v.as_ref() else {
                panic!("Expected string for input '{input}'");
            };
            assert_eq!(&**s, expected, "input: '{input}'");
        }
    }

    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_string()).collect()
    }

    #[test]
    fn parse_run_captures_trailing_args_raw() {
        let args = args(&["run", "list", "-al", "/tmp", "--color=auto"]);
        let (_, command) = parse(&args).unwrap();
        let Command::Run { job, value_map, trailing_args, as_test, derive_cache_key } = command else {
            panic!("expected run command");
        };
        assert_eq!(job, "list");
        assert!(value_map.entries().is_empty());
        assert_eq!(trailing_args, &args[2..]);
        assert!(!as_test);
        assert!(!derive_cache_key);
    }

    #[test]
    fn parse_run_keeps_prefix_options_and_vars() {
        let args = args(&["run", "--derive-cache-key", "--limit=5", "build", "--release"]);
        let (_, command) = parse(&args).unwrap();
        let Command::Run { job, value_map, trailing_args, as_test, derive_cache_key } = command else {
            panic!("expected run command");
        };
        assert_eq!(job, "build");
        assert_eq!(value_map["limit"].as_i64(), Some(5));
        assert_eq!(trailing_args, &args[4..]);
        assert!(!as_test);
        assert!(derive_cache_key);
    }

    #[test]
    fn parse_task_params_preserves_legacy_var_parsing() {
        let args = args(&["--msg=hello", r#"{"count":2}"#]);
        let params = parse_task_params(&args).unwrap();
        let ValueRef::String(msg) = params["msg"].as_ref() else {
            panic!("expected msg string");
        };
        assert_eq!(&**msg, "hello");
        assert_eq!(params["count"].as_i64(), Some(2));
    }

    #[test]
    fn parse_task_params_rejects_unknown_short_flags() {
        let args = args(&["-al"]);
        let err = parse_task_params(&args).unwrap_err();
        assert!(err.to_string().contains("Unknown flag -a"), "unexpected error: {err}");
    }

    #[test]
    fn parse_run_trailing_params_preserves_post_task_run_options_for_legacy_tasks() {
        let args = args(&["--as-test", "--derive-cache-key", "--msg=hello"]);
        let mut as_test = false;
        let mut derive_cache_key = false;
        let params = parse_run_trailing_params(&args, &mut as_test, &mut derive_cache_key).unwrap();
        assert!(as_test);
        assert!(derive_cache_key);
        let ValueRef::String(msg) = params["msg"].as_ref() else {
            panic!("expected msg string");
        };
        assert_eq!(&**msg, "hello");
    }

    #[test]
    fn parse_complete_forward_prefix_requires_task() {
        let cli_args = args(&["self", "complete", "forward-prefix", "--task=ls"]);
        let (_, command) = parse(&cli_args).unwrap();
        let Command::Complete { context: CompleteContext::ForwardPrefix { task } } = command else {
            panic!("expected forward-prefix completion context");
        };
        assert_eq!(task, "ls");

        let cli_args = args(&["self", "complete", "forward-prefix"]);
        let err = parse(&cli_args).err().unwrap();
        assert!(err.to_string().contains("complete forward-prefix requires --task=NAME"), "unexpected error: {err}");
    }

    #[test]
    fn parse_complete_task_args_accepts_task_and_exclude() {
        let cli_args =
            args(&["self", "complete", "task-args", "--task=ls", "--exclude=args,other", "--", "--env", "x"]);
        let (_, command) = parse(&cli_args).unwrap();
        let Command::Complete { context: CompleteContext::TaskArgs { task, exclude, args } } = command else {
            panic!("expected task-args completion context");
        };
        assert_eq!(task, "ls");
        assert_eq!(exclude, vec!["args", "other"]);
        assert_eq!(args, &["--env".to_string(), "x".to_string()]);
    }

    #[test]
    fn parse_logs_help() {
        let cli_args = args(&["logs", "--help"]);
        let (_, command) = parse(&cli_args).unwrap();
        let Command::Help(topic) = command else {
            panic!("expected help command");
        };
        assert_eq!(topic, HelpTopic::Logs);
    }

    #[test]
    fn parse_builtin_subcommand_help_topics() {
        let cases = [
            (&["global", "--help"][..], HelpTopic::Global),
            (&["run", "--help"][..], HelpTopic::Run),
            (&["exec", "--help"][..], HelpTopic::Exec),
            (&["start", "--help"][..], HelpTopic::Start),
            (&["restart", "--help"][..], HelpTopic::Restart),
            (&["restart-selected", "--help"][..], HelpTopic::RestartSelected),
            (&["stop", "--help"][..], HelpTopic::Stop),
            (&["status", "--help"][..], HelpTopic::Status),
            (&["test", "--help"][..], HelpTopic::Test),
            (&["rerun-tests", "--help"][..], HelpTopic::RerunTests),
            (&["logs", "--help"][..], HelpTopic::Logs),
            (&["get", "--help"][..], HelpTopic::Get),
            (&["get", "workspace", "--help"][..], HelpTopic::GetWorkspace),
            (&["get", "workspace", "config-path", "--help"][..], HelpTopic::GetWorkspaceConfigPath),
            (&["get", "workspaces", "--help"][..], HelpTopic::GetWorkspaces),
            (&["get", "default-user-config", "--help"][..], HelpTopic::GetDefaultUserConfig),
            (&["get", "logged-rust-panics", "--help"][..], HelpTopic::GetLoggedRustPanics),
            (&["function", "--help"][..], HelpTopic::Function),
            (&["function", "call", "--help"][..], HelpTopic::FunctionCall),
            (&["completions", "--help"][..], HelpTopic::Completions),
            (&["self", "--help"][..], HelpTopic::SelfCommand),
            (&["self", "server", "--help"][..], HelpTopic::SelfServer),
            (&["self", "validate", "--help"][..], HelpTopic::SelfValidate),
            (&["self", "logs", "--help"][..], HelpTopic::SelfLogs),
            (&["self", "complete", "--help"][..], HelpTopic::SelfComplete),
        ];

        for (values, expected) in cases {
            let cli_args = args(values);
            let (_, command) = parse(&cli_args).unwrap();
            let Command::Help(topic) = command else {
                panic!("expected help command for {values:?}");
            };
            assert_eq!(topic, expected, "args: {values:?}");
        }
    }

    #[test]
    fn parse_status_accepts_no_name() {
        let cli_args = args(&["status"]);
        let (_, command) = parse(&cli_args).unwrap();
        let Command::Status { name } = command else {
            panic!("expected status command");
        };
        assert_eq!(name, None);
    }

    #[test]
    fn parse_run_help_before_task_but_preserves_trailing_task_help() {
        let cli_args = args(&["run", "--help"]);
        let (_, command) = parse(&cli_args).unwrap();
        let Command::Help(topic) = command else {
            panic!("expected help command");
        };
        assert_eq!(topic, HelpTopic::Run);

        let cli_args = args(&["run", "build", "--help"]);
        let (_, command) = parse(&cli_args).unwrap();
        let Command::Run { job, trailing_args, .. } = command else {
            panic!("expected run command");
        };
        assert_eq!(job, "build");
        assert_eq!(trailing_args, &cli_args[2..]);
    }
}
