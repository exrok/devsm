use anyhow::{Context, bail};
use jsony_value::{Value, ValueMap};

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

pub struct GlobalArguments<'a> {
    pub from: Option<&'a str>,
}

pub enum Command<'a> {
    Tui,
    Server,
    RestartSelected,
    Restart { job: &'a str, value_map: ValueMap<'a> },
    Exec { job: &'a str, value_map: ValueMap<'a> },
    Run { job: &'a str, value_map: ValueMap<'a> },
    Test { filters: Vec<TestFilter<'a>> },
    Validate { path: Option<&'a str>, skip_path_checks: bool },
    Get { resource: GetResource },
}

pub enum GetResource {
    SelfLogs,
}

/// Filter for test selection.
/// - `+tag`: Include tests with this tag (OR combined with other includes)
/// - `-tag`: Exclude tests with this tag (absolute exclusion, applied first)
/// - `name`: Include tests with this name (OR combined with other includes)
#[derive(Debug, Clone)]
pub enum TestFilter<'a> {
    IncludeTag(&'a str),
    ExcludeTag(&'a str),
    IncludeName(&'a str),
}

/// Parses a job name and parameters from remaining arguments.
///
/// Accepts either `--key=value` flags or a single JSON object literal.
/// Flags are parsed as JSON literals, falling back to strings.
fn parse_job_args<'a>(parser: &mut ArgParser<'a>) -> anyhow::Result<(&'a str, ValueMap<'a>)> {
    let job = match parser.next() {
        Some(Component::Term(name)) => name,
        Some(f) => bail!("Expected name of job, found {:?}", f),
        None => bail!("Missing name of job"),
    };

    let mut value_map = ValueMap::new();
    while let Some(component) = parser.next() {
        match component {
            Component::Long(key) => {
                let Some(Component::Value(val)) = parser.next() else {
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

    Ok((job, value_map))
}

fn parse_restart<'a>(parser: &mut ArgParser<'a>) -> anyhow::Result<Command<'a>> {
    let (job, value_map) = parse_job_args(parser)?;
    Ok(Command::Restart { job, value_map })
}

fn parse_exec<'a>(parser: &mut ArgParser<'a>) -> anyhow::Result<Command<'a>> {
    let (job, value_map) = parse_job_args(parser)?;
    Ok(Command::Exec { job, value_map })
}

fn parse_run<'a>(parser: &mut ArgParser<'a>) -> anyhow::Result<Command<'a>> {
    let (job, value_map) = parse_job_args(parser)?;
    Ok(Command::Run { job, value_map })
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
                "skip-path-checks" => skip_path_checks = true,
                _ => bail!("Unknown flag --{} in validate command", long),
            },
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
    Ok(Command::Validate { path, skip_path_checks })
}

/// Parse test filters from remaining arguments.
/// - `+tag` includes tests with tag
/// - `-tag` excludes tests with tag
/// - `name` includes tests with name
fn parse_test_filters<'a>(parser: &mut ArgParser<'a>) -> anyhow::Result<Command<'a>> {
    let mut filters = Vec::new();
    for component in parser.by_ref() {
        match component {
            Component::Term(arg) => {
                if let Some(tag) = arg.strip_prefix('+') {
                    filters.push(TestFilter::IncludeTag(tag));
                } else if let Some(tag) = arg.strip_prefix('-') {
                    filters.push(TestFilter::ExcludeTag(tag));
                } else {
                    filters.push(TestFilter::IncludeName(arg));
                }
            }
            Component::Long(long) => {
                bail!("Unexpected flag --{} in test command", long);
            }
            Component::Flags(flags) => {
                // Check if this is actually a negative tag filter (e.g., -slow)
                // Single-character flags starting with a letter are treated as exclude tags
                if !flags.is_empty() && flags.chars().next().map(|c| c.is_alphabetic()).unwrap_or(false) {
                    filters.push(TestFilter::ExcludeTag(flags));
                } else if let Some(flag) = flags.chars().next() {
                    bail!("Unknown flag -{}", flag);
                }
            }
            Component::Value(val) => {
                bail!("Unexpected value: {:?}", val);
            }
        }
    }
    Ok(Command::Test { filters })
}

pub fn parse<'a>(args: &'a [String]) -> anyhow::Result<(GlobalArguments<'a>, Command<'a>)> {
    let mut parser = ArgParser::new(args);
    let mut global = GlobalArguments { from: None };

    let command = 'command: loop {
        let Some(arg) = parser.next() else {
            break 'command Command::Tui;
        };
        match arg {
            Component::Flags(flags) => {
                if let Some(flag) = flags.chars().next() {
                    bail!("Unknown flag, -{}", flag)
                }
            }
            Component::Long(long) => {
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
                "server" => break 'command Command::Server,
                "restart-selected" => break 'command Command::RestartSelected,
                "restart" => break 'command parse_restart(&mut parser)?,
                "exec" => break 'command parse_exec(&mut parser)?,
                "run" => break 'command parse_run(&mut parser)?,
                "test" => break 'command parse_test_filters(&mut parser)?,
                "validate" => break 'command parse_validate(&mut parser)?,
                "get" => {
                    let Some(Component::Term(resource)) = parser.next() else {
                        bail!("get requires a resource name");
                    };
                    match resource {
                        "self-logs" => break 'command Command::Get { resource: GetResource::SelfLogs },
                        _ => bail!("Unknown resource: {}", resource),
                    }
                }
                unknown_command => bail!("Unknown Command: {:?}", unknown_command),
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

        let v = parse_flag_value("3.14");
        let ValueRef::Number(n) = v.as_ref() else { panic!() };
        assert_eq!(n.as_f64(), Some(3.14));

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
}
