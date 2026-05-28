#!/usr/bin/env bash
# Bash completion test driver. Drives _devsm with simulated COMP_LINE/COMP_POINT
# and asserts that COMPREPLY contains the expected candidates.

set -eu

# Re-exec under bash if invoked under another sh (the test entry uses `sh =`).
if [ -z "${BASH_VERSION:-}" ]; then
    if command -v bash >/dev/null 2>&1; then
        exec bash "$0" "$@"
    fi
    echo "SKIP: bash not installed"
    exit 0
fi

THIS_DIR="$(cd "$(dirname "$0")" && pwd)"
. "$THIS_DIR/harness.sh"

# Load the completion script as emitted by the binary (this is what users
# actually get when running `devsm completions bash`).
source <("$DEVSM_BIN" completions bash)

if ! declare -F _devsm >/dev/null; then
    echo "FAIL: _devsm function not loaded from 'devsm completions bash'"
    exit 1
fi

# drive "<line>"  →  populates COMPREPLY by calling _devsm with COMP_LINE/POINT
drive() {
    COMP_LINE="$1"
    COMP_POINT=${#COMP_LINE}
    # Initialise COMP_WORDS minimally; _devsm rebuilds its own _devsm_words.
    read -ra COMP_WORDS <<< "$COMP_LINE"
    COMP_CWORD=$((${#COMP_WORDS[@]} - 1))
    COMPREPLY=()
    _devsm
}

echo "== bash completion tests =="

drive "devsm "
reply="${COMPREPLY[*]:-}"
assert_contains "run" "$reply" "top-level: run"
assert_contains "exec" "$reply" "top-level: exec"
assert_contains "completions" "$reply" "top-level: completions"
assert_contains "status" "$reply" "top-level: status"
assert_contains "build" "$reply" "top-level: task 'build'"
assert_contains "api" "$reply" "top-level: task 'api'"
assert_contains "all" "$reply" "top-level: group 'all'"

drive "devsm run "
reply="${COMPREPLY[*]:-}"
assert_contains "build" "$reply" "run: 'build'"
assert_contains "api" "$reply" "run: 'api'"
assert_contains "all" "$reply" "run: group 'all'"
assert_contains "api:dev" "$reply" "run: profile variant 'api:dev'"
assert_contains "api:release" "$reply" "run: profile variant 'api:release'"

drive "devsm exec "
reply="${COMPREPLY[*]:-}"
assert_contains "build" "$reply" "exec: 'build'"
assert_not_contains "all" "$reply" "exec: NO group 'all'"

drive "devsm run api:"
reply="${COMPREPLY[*]:-}"
assert_contains "api:dev" "$reply" "run api:: profile 'api:dev'"
assert_contains "api:release" "$reply" "run api:: profile 'api:release'"

drive "devsm run deploy "
reply="${COMPREPLY[*]:-}"
assert_contains "--host=" "$reply" "deploy vars: --host="
assert_contains "--port=" "$reply" "deploy vars: --port="

drive "devsm run deploy --host=localhost "
reply="${COMPREPLY[*]:-}"
assert_contains "--port=" "$reply" "deploy after --host: --port="
assert_not_contains "--host=" "$reply" "deploy after --host: --host= excluded"

drive "devsm status "
reply="${COMPREPLY[*]:-}"
assert_contains "build" "$reply" "status: task 'build'"
assert_contains "all" "$reply" "status: group 'all'"

drive "devsm completions "
reply="${COMPREPLY[*]:-}"
assert_contains "bash" "$reply" "completions: bash"
assert_contains "fish" "$reply" "completions: fish"
assert_contains "zsh" "$reply" "completions: zsh"

drive "devsm self "
reply="${COMPREPLY[*]:-}"
assert_contains "server" "$reply" "self: server"
assert_contains "validate" "$reply" "self: validate"
assert_contains "logs" "$reply" "self: logs"
assert_contains "complete" "$reply" "self: complete"

drive "devsm logs --kind="
reply="${COMPREPLY[*]:-}"
assert_contains "--kind=service" "$reply" "logs --kind=service"
assert_contains "--kind=action" "$reply" "logs --kind=action"

drive "devsm test "
reply="${COMPREPLY[*]:-}"
assert_contains "unit" "$reply" "test: 'unit'"
assert_contains "+fast" "$reply" "test: '+fast'"
assert_contains "-slow" "$reply" "test: '-slow'"

drive "devsm function "
reply="${COMPREPLY[*]:-}"
assert_contains "call" "$reply" "function: 'call'"

drive "devsm function call "
reply="${COMPREPLY[*]:-}"
assert_contains "restart_api" "$reply" "function call: 'restart_api'"

# Namespace + shadowing
drive "devsm run group."
reply="${COMPREPLY[*]:-}"
assert_contains "group.all" "$reply" "namespaced: group.all"
assert_contains "group.logs" "$reply" "namespaced: group.logs (shadowed bare retained as namespaced)"
assert_not_contains "all" "$reply" "namespaced: 'all' bare suppressed when 'group.' prefix"

drive "devsm run action."
reply="${COMPREPLY[*]:-}"
assert_contains "action.build" "$reply" "namespaced: action.build"
assert_contains "action.run" "$reply" "namespaced: action.run available though bare is shadowed"

# 'logs' is a builtin command, so bare 'logs' from the group is suppressed in
# the runnable position (would conflict with the builtin and is unreachable).
drive "devsm run "
reply="${COMPREPLY[*]:-}"
assert_not_contains "logs" "$reply" "shadow: bare 'logs' runnable suppressed (group shadowed by builtin)"
assert_contains "group.logs" "$reply" "shadow: 'group.logs' namespaced still available"

# Action 'run' collides with builtin 'run'. Top-level: 'run' is the builtin.
# Action is reachable only via 'action.run'.
drive "devsm "
reply="${COMPREPLY[*]:-}"
assert_contains "action.run" "$reply" "shadow: action.run available though bare is shadowed"

report_and_exit
