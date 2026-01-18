# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

devsm is a TUI (Terminal User Interface) development service manager written in Rust. It manages services and actions during development workflows, providing aggregated log views with powerful filtering. The tool is optimized to help developers stay in the zone when switching between services, running tests at various levels, and switching between profiles and git branches.

Configuration is defined in `devsm.toml` which specifies all actions, services, and tests for a workspace along with their dependencies.

## Build and Development Commands

### Building

```bash
cargo build                 # Debug build
cargo build --release       # Release build with debug symbols
```

### Running

```bash
cargo run -- server         # Start the daemon
cargo run                   # Start the TUI client (looks for devsm.toml in current/parent directories)
```

### Testing

```bash
cargo test                  # Run all tests
```

## Architecture

### Client-Daemon Model

The application uses a multi-process architecture:

1. **Daemon Process** (`daemon.rs`): Long-running background server that manages all workspaces and processes

   - Listens on Unix domain socket at `/tmp/.devsm.socket`
   - Automatically spawned by clients if not running
   - Uses `setsid()` to detach from controlling terminal
   - Handles multiple workspace configurations simultaneously

2. **Client Process** (`main.rs::client()`): Interactive TUI that connects to daemon

   - Sends stdin/stdout file descriptors to daemon using `sendfd`
   - Communicates via Unix socket with binary protocol (using `jsony` crate)
   - Signal handlers for SIGTERM, SIGINT, SIGWINCH

3. **TUI Thread** (`tui.rs`): Runs in daemon but displays in client's terminal
   - Uses `vtui` crate for terminal rendering
   - Receives terminal FDs from client via `sendfd`
   - Event loop handles keyboard, mouse, and resize events

### Configuration System

Configuration parsing happens in `config.rs` and `config/toml_handler.rs`:

- **TOML-based**: Tasks defined in `devsm.toml`
- **Expression System**: Supports conditional expressions, template literals, and variable substitution
  - `StringExpr`: String literals, variables (`$var`), template literals (`` `text ${$var}` ``), conditionals
  - `StringListExpr`: For command arguments with variable expansion
  - `AliasListExpr`: For task dependencies
  - Conditionals: `{ if = {profile = "production"}, then =  "--release" }`
- **Evaluation with Bump Allocator**: Expressions are parsed once and evaluated per-execution with different environments
- **Task Types**: `Service` (long-running) and `Action` (run-once)
- **Command Styles**: Either `cmd` (array of args) or `sh` (shell script string)

### Process Management

The `process_manager.rs` orchestrates all subprocess lifecycle:

- **MIO-based Event Loop**: Non-blocking I/O for all process pipes and client sockets
- **Process Spawning**:
  - Sets process group (`setpgid(0, 0)`) for proper cleanup of nested processes
  - Sets `PR_SET_PDEATHSIG` to SIGTERM so children die if parent dies
  - Pipes stdout/stderr for log capture
  - For `sh` commands, pipes script to stdin
- **Output Capture**: Buffered line-by-line reading with ANSI escape sequence parsing
- **Signal Handling**: SIGINT sent to process group for termination
- **Wait Thread**: Dedicated thread calling `wait()` to reap child processes

### Workspace and Job Scheduling

The `workspace.rs` module manages task execution state:

- **BaseTask**: Configuration template for a task (never executed, just config)
- **Job**: Specific execution instance of a BaseTask with runtime state
- **Job States**: Scheduled → Starting → Running → Exited/Cancelled
- **Dependency System**:
  - `before`: Tasks that must complete before each run
  - `before_once`: Tasks that only need to complete successfully once
  - Dependency predicates: `Terminated`, `TerminatedNaturallyAndSuccessfully`, `Active`
- **JobIndexList** (`workspace/job_index_list.rs`): Compact in-place partitioning of jobs by state
- **Scheduling**: Brute-force scan for ready tasks (marked TODO for optimization)
- **Config Hot-Reload**: Watches `devsm.toml` modification time and reloads automatically

### Logging System

The `log_storage.rs` module provides a circular buffer for process output:

- **JobLogCorrelation**: Encodes base task index + per-task job counter in u32
- **LogWriter/Logs**: Thread-safe circular buffer with reader/writer split
- **ANSI Handling**: Preserves terminal styling in logs (via `line_width.rs`)
- **Log Modes** (in TUI):
  - `All`: Show all task output
  - `OnlySelected`: Show only selected task
  - `Hybrid`: Show selected task plus errors from others

### TUI Components

The `tui.rs` module and submodules render the interface:

- **Layout**: Split screen with log views (top) and task/job trees (bottom)
- **task_tree.rs**: Hierarchical view of BaseTasks and their Jobs
- **log_stack.rs**: Dual log pane with configurable filtering
- **select_search.rs**: Fuzzy-searchable selection menus for groups/profiles
- **Rendering**: Double-buffered with `vtui::DoubleBuffer` for flicker-free updates
- **Input Handling**: Vim-style keybindings (j/k for navigation, h/l for focus)

## Configuration File Format

The `devsm.toml` format supports:

```toml
[action.task_name]
cmd = ["command", "arg1", { if.profile = "prod", then = "--release" }]
sh = "shell script"  # Alternative to cmd
pwd = "working/directory"  # Default is "./"
profiles = ["default", "prod"]
before = ["dependency_task"]  # Run before each execution
before_once = ["build"]  # Run once before first execution

[service.service_name]
cmd = ["long-running-command"]
# Services are restarted if already running

[group]
group_name = [["task1:profile", { var = "value" }], "task2"]
```

Template literals with variable substitution:

```toml
sh = '''echo "Hello ${$name}" && echo "Value: ${$value}"'''
```

## Key Dependencies

- **jsony**: Custom binary/JSON serialization for IPC (fast, zero-copy)
- **jsony_value**: Dynamic value types for parameter passing
- **vtui**: Custom TUI rendering library (path dependency)
- **mio**: Non-blocking I/O and event loop
- **bumpalo**: Bump allocator for expression evaluation (avoid global allocations)
- **toml-span**: TOML parser with span tracking for error reporting
- **kvlog**: Structured logging to `/tmp/.devsm.log` (daemon) and `/tmp/.client.devsm.log` (client)

## Special Features

### Auto-generated Cargo Tasks

The `~cargo` built-in task allows running arbitrary cargo commands:

```bash
# Uses CARGO_AUTO_EXPR which accepts variable args
devsm run ~cargo -- args=["build", "--release"]
```

### Rust Panic Detection

The workspace can extract panic locations from logs via `extract_rust_panic_from_line()` in `workspace.rs` to help navigate to failing code.

### Profile System

Tasks can define multiple profiles with conditional configuration. Profiles affect:

- Command arguments (via `if.profile` conditionals)
- Which task variant to spawn

## Development Patterns

- **Leak for 'static**: Config strings are `.leak()`ed to obtain `'static` lifetime (simplified memory model)
- **Unsafe Transmute**: Used to extend lifetimes in bump-allocated expressions
- **Manual Signal Handling**: Direct `libc::sigaction` usage for precise signal control
- **Zero-copy**: Extensive use of `try_zerocopy` in parsing to avoid allocations
