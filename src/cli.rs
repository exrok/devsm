use anyhow::{Context, bail};
use jsony_value::ValueMap;

struct ArgParser<'a> {
    args: std::slice::Iter<'a, String>,
    value: Option<&'a str>,
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

        return Some(Component::Term(arg));
    }
}

pub struct GlobalArguments<'a> {
    pub from: Option<&'a str>,
}

pub enum Command<'a> {
    Cli,
    Server,
    RestartSelected,
    TriggerPrimary,
    TriggerSecondary,
    Run { job: &'a str, value_map: jsony_value::ValueMap<'a> },
}

fn parse_run<'a>(parser: &mut ArgParser<'a>) -> anyhow::Result<Command<'a>> {
    let job = match parser.next() {
        Some(Component::Term(name)) => name,
        Some(f) => bail!("Expected name of job, found {:?}", f),
        None => bail!("Missing name of job"),
    };
    let value_map: ValueMap = match parser.next() {
        Some(Component::Term(value)) => jsony::from_json(value).context("Parsing run value")?,
        Some(f) => bail!("Expected optional job parameter json map, found {:?}", f),
        None => ValueMap::new(),
    };
    Ok(Command::Run { job, value_map })
}

pub fn parse<'a>(args: &'a [String]) -> anyhow::Result<(GlobalArguments<'a>, Command<'a>)> {
    let mut parser = ArgParser::new(args);
    let mut global = GlobalArguments { from: None };

    let command = 'command: loop {
        let Some(arg) = parser.next() else {
            break 'command Command::Cli;
        };
        match arg {
            Component::Flags(flags) => {
                for flag in flags.chars() {
                    bail!("Unknown flag, -{}", flag)
                }
            }
            Component::Long(long) => match long {
                "from" => {
                    if let Some(Component::Long(value) | Component::Value(value)) = parser.next() {
                        if global.from.is_some() {
                            bail!("from already specified")
                        }
                        global.from = Some(value);
                    } else {
                        bail!("Expected value after from");
                    }
                }
                _ => {}
            },
            Component::Value(value) => {
                bail!("Dangling value found: {:?}", value)
            }
            Component::Term(command) => match command {
                "server" => break 'command Command::Server,
                "restart-selected" => break 'command Command::RestartSelected,
                "run" => break 'command parse_run(&mut parser)?,
                unknown_command => bail!("Unknown Command: {:?}", unknown_command),
            },
        }
    };

    Ok((global, command))
}
