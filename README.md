# devsm: The TUI Development Service Manager

WIP; Additional documentation in the works.

devsm manages your services, tests and scripts:
- Manages service lifetimes and task dependencies
- Dispatch from anyway where in the repo
- TUI based dashboard for lunching services, tests and logs

## Installation

devsm is still alpha and under active development, expect breaking changes.

The easiest installation is currently through cargo from the git repo:

```sh
cargo install --git https://github.com/exrok/devsm --force devsm
```

## Workspace options

Declare choices in `devsm.toml` to share Docker and native infrastructure configurations:

```toml
[option.infra]
choices = ["docker", "native"]
default = "docker"
info = "native requires postgres, initdb and mosquitto on PATH"

[service.postgres]
cmd = { if.option.infra = "docker", then = "./cmd/postgres.docker.sh", else = "./cmd/postgres.native.sh" }

[service.mqtt]
cmd = { if.option.infra = "docker", then = "./cmd/mqtt.docker.sh", else = "./cmd/mqtt.native.sh" }
```

Select a backend for this checkout in `devsm.local.toml`, next to `devsm.toml`:

```toml
[option]
infra = "native"
```

Add `devsm.local.toml` to your project's `.gitignore`. It accepts only option values.
Local values take precedence over declared defaults; an option without a default
must be set locally. Names use lowercase letters, digits and underscores. Invalid
choices are errors; unknown local option names produce warnings so values left
over from another branch do not prevent loading.

`if.option` works in `cmd`, `sh`, `pwd`, `env`, `require` and `ready`, including
nested expressions and variable references. `else` and `or_else` are aliases.
A false branch without either omits a list item, environment entry or readiness
condition. For example:

```toml
[action.init_db]
cmd = { if.option.infra = "docker", then = ["docker", "exec", "dev_pg", "psql"], else = ["psql"] }
require = [{ if.option.infra = "native", then = "initdb" }]
cache = {}
```

Cached tasks automatically include every option their expressions reference in
their cache keys, including persistent caches. Unreferenced options do not affect
their caches. Local-file creation, edits and removal use the same reload path as
`devsm.toml`: subsequent launches and TUI config reloads see the new values.
Running services keep their current configuration until explicitly restarted.
The TUI status bar shows the loaded option values when no status message is active.
Options are shared by all clients of the workspace; there are no environment or
CLI overrides.

Editor schemas are available in `schema/devsm.json` and `schema/devsm.local.json`.




