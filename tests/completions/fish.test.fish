#!/usr/bin/env fish
# Fish completion test driver. Uses `complete -C <line>` to drive completion.

if not type -q fish
    echo "SKIP: fish not installed"
    exit 0
end

set THIS_DIR (cd (dirname (status -f)); and pwd)
set REPO_ROOT (cd "$THIS_DIR/../.."; and pwd)
set TARGET_DIR (test -d /tmp/rust-target && echo /tmp/rust-target; or echo "$REPO_ROOT/target")
set DEVSM_BIN "$TARGET_DIR/debug/devsm"

if not test -x "$DEVSM_BIN"
    echo "harness: $DEVSM_BIN not found"
    exit 1
end

cd "$THIS_DIR/workspace"
set -gx PATH "$TARGET_DIR/debug" $PATH
set -gx DEVSM_NO_AUTO_SPAWN 1

# Block any user-installed devsm completion (e.g. ~/.config/fish/completions/devsm.fish)
# from auto-loading and conflicting with the fresh copy this test sources below.
# Restrict fish's completion lookup to a private empty directory.
set -l ISOLATED_FCD (mktemp -d)
set -g fish_complete_path "$ISOLATED_FCD"

# Source the script as emitted by the binary.
$DEVSM_BIN completions fish | source

set -g TEST_COUNT 0
set -g TEST_FAILURES 0

function assert_contains
    set -l needle $argv[1]
    set -l haystack $argv[2]
    set -l label $argv[3]
    set TEST_COUNT (math $TEST_COUNT + 1)
    if string match -q -- "* $needle *" " $haystack "
        echo "  ok: $label"
    else
        set TEST_FAILURES (math $TEST_FAILURES + 1)
        echo "  FAIL: $label"
        echo "    expected to contain: [$needle]"
        echo "    actual: [$haystack]"
    end
end

function assert_not_contains
    set -l needle $argv[1]
    set -l haystack $argv[2]
    set -l label $argv[3]
    set TEST_COUNT (math $TEST_COUNT + 1)
    if string match -q -- "* $needle *" " $haystack "
        set TEST_FAILURES (math $TEST_FAILURES + 1)
        echo "  FAIL: $label"
        echo "    expected NOT to contain: [$needle]"
        echo "    actual: [$haystack]"
    else
        echo "  ok: $label"
    end
end

function comp_for
    # complete -C emits one candidate per line; flatten via tr.
    complete -C "$argv[1]" 2>/dev/null | string split \t -f 1 | string join ' '
end

echo "== fish completion tests =="

set reply (comp_for "devsm ")
assert_contains "run" "$reply" "top-level: run"
assert_contains "completions" "$reply" "top-level: completions"
assert_contains "status" "$reply" "top-level: status"
assert_contains "build" "$reply" "top-level: task 'build'"
assert_contains "api" "$reply" "top-level: task 'api'"
assert_contains "all" "$reply" "top-level: group 'all'"

set reply (comp_for "devsm status ")
assert_contains "build" "$reply" "status: task 'build'"
assert_contains "all" "$reply" "status: group 'all'"

set reply (comp_for "devsm run ")
assert_contains "build" "$reply" "run: 'build'"
assert_contains "api" "$reply" "run: 'api'"
assert_contains "all" "$reply" "run: group 'all'"
assert_contains "api:dev" "$reply" "run: profile variant 'api:dev'"

set reply (comp_for "devsm exec ")
assert_contains "build" "$reply" "exec: 'build'"
assert_not_contains "all" "$reply" "exec: NO group 'all'"

set reply (comp_for "devsm run api:")
assert_contains "api:dev" "$reply" "run api:: 'api:dev'"
assert_contains "api:release" "$reply" "run api:: 'api:release'"

set reply (comp_for "devsm run deploy ")
assert_contains "--host=" "$reply" "deploy vars: --host="
assert_contains "--port=" "$reply" "deploy vars: --port="

set reply (comp_for "devsm run deploy --host=x ")
assert_contains "--port=" "$reply" "deploy after --host: --port="
assert_not_contains "--host=" "$reply" "deploy after --host: --host= excluded"

set reply (comp_for "devsm completions ")
assert_contains "bash" "$reply" "completions: bash"
assert_contains "fish" "$reply" "completions: fish"
assert_contains "zsh" "$reply" "completions: zsh"

set reply (comp_for "devsm self ")
assert_contains "server" "$reply" "self: server"
assert_contains "validate" "$reply" "self: validate"

set reply (comp_for "devsm test ")
assert_contains "unit" "$reply" "test: 'unit'"
assert_contains "+fast" "$reply" "test: '+fast'"
assert_contains "-slow" "$reply" "test: '-slow'"

set reply (comp_for "devsm function call ")
assert_contains "restart_api" "$reply" "function call: 'restart_api'"

# Namespace + shadowing
set reply (comp_for "devsm run group.")
assert_contains "group.all" "$reply" "namespaced: group.all"
assert_contains "group.logs" "$reply" "namespaced: group.logs (shadowed bare retained)"

set reply (comp_for "devsm run action.")
assert_contains "action.build" "$reply" "namespaced: action.build"
assert_contains "action.run" "$reply" "namespaced: action.run (bare shadowed by builtin)"

set reply (comp_for "devsm run ")
assert_not_contains "logs" "$reply" "shadow: bare 'logs' runnable suppressed"
assert_contains "group.logs" "$reply" "shadow: 'group.logs' namespaced still available"

echo ""
echo "$TEST_COUNT assertions, $TEST_FAILURES failures"
exit $TEST_FAILURES
