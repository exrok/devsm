#!/usr/bin/env zsh
# Zsh completion test driver. Since zsh's completion system is tightly coupled
# to the line editor, we test the script in two layers:
#   1. Syntax: `zsh -n` (verified separately during build)
#   2. Behaviour: mock _describe / _files / _arguments and invoke the helper
#      functions and the dispatcher with synthetic $words / $CURRENT state.

emulate -L zsh

if ! command -v zsh >/dev/null 2>&1; then
    print "SKIP: zsh not installed"
    exit 0
fi

THIS_DIR=${0:A:h}
REPO_ROOT=${THIS_DIR:h:h}
TARGET_DIR="/tmp/rust-target"
[[ -d "$TARGET_DIR" ]] || TARGET_DIR="$REPO_ROOT/target"
DEVSM_BIN="$TARGET_DIR/debug/devsm"

if [[ ! -x "$DEVSM_BIN" ]]; then
    print "harness: $DEVSM_BIN not found" >&2
    exit 1
fi

cd "$THIS_DIR/workspace"
path=("$TARGET_DIR/debug" $path)
export PATH
export DEVSM_NO_AUTO_SPAWN=1

# Capture every _describe candidate (and _files calls) into one global array.
typeset -ga CAPTURED

_describe() {
    # _describe -t TAG 'desc' ARRAY [...flags]
    # The array name is at $3 (after -t TAG 'desc'). Or just iterate args looking
    # for the array name.
    local i array_name=""
    for ((i = 1; i <= $#; i++)); do
        case "${argv[i]}" in
            -t) (( i++ )); continue ;;
            -*) continue ;;
            *)
                if [[ -z "$array_name" ]]; then
                    # First non-flag, non-tag-value arg is the description string
                    array_name="skip"
                else
                    array_name="${argv[i]}"
                    break
                fi
                ;;
        esac
    done
    if [[ -n "$array_name" && "$array_name" != "skip" ]]; then
        local entry val
        for entry in "${(@P)array_name}"; do
            # _describe accepts "value:description" with literal ':' in the value
            # escaped as '\:'. Substitute a placeholder so we can split safely.
            val="${entry//\\:/__COLON__}"
            val="${val%%:*}"
            val="${val//__COLON__/:}"
            CAPTURED+=("$val")
        done
    fi
}

_files() { CAPTURED+=("__FILES__"); }
_directories() { CAPTURED+=("__DIRS__"); }
_message() { :; }

# Source the script body. The bottom of the script auto-invokes _devsm when
# loaded by compdef, but at source-time the funcstack[1] check is false so it
# only registers compdef. We want the function definitions only.
source <($DEVSM_BIN completions zsh)

# Smoke check: required helper functions exist.
typeset -i TEST_COUNT=0
typeset -i TEST_FAILURES=0

assert_contains() {
    local needle="$1" haystack="$2" label="$3"
    (( TEST_COUNT++ ))
    if [[ " $haystack " == *" $needle "* ]]; then
        print "  ok: $label"
    else
        (( TEST_FAILURES++ ))
        print "  FAIL: $label"
        print "    expected to contain: [$needle]"
        print "    actual: [$haystack]"
    fi
}

assert_not_contains() {
    local needle="$1" haystack="$2" label="$3"
    (( TEST_COUNT++ ))
    if [[ " $haystack " == *" $needle "* ]]; then
        (( TEST_FAILURES++ ))
        print "  FAIL: $label"
        print "    expected NOT to contain: [$needle]"
        print "    actual: [$haystack]"
    else
        print "  ok: $label"
    fi
}

run_helper() {
    CAPTURED=()
    "$@"
}

print "== zsh completion tests =="

# Verify the major helpers exist.
for fn in _devsm _devsm_commands _devsm_runnables _devsm_tasks_only _devsm_tests \
          _devsm_kinds _devsm_functions _devsm_self_commands _devsm_get_resources \
          _devsm_test_filters _devsm_vars_only _devsm_task_args; do
    (( TEST_COUNT++ ))
    if (( $+functions[$fn] )); then
        print "  ok: function $fn defined"
    else
        (( TEST_FAILURES++ ))
        print "  FAIL: function $fn missing"
    fi
done

run_helper _devsm_runnables
reply="${(j: :)CAPTURED}"
assert_contains "build" "$reply" "runnables: build"
assert_contains "api" "$reply" "runnables: api"
assert_contains "api:dev" "$reply" "runnables: api:dev"
assert_contains "all" "$reply" "runnables: group 'all'"

run_helper _devsm_tasks_only
reply="${(j: :)CAPTURED}"
assert_contains "build" "$reply" "tasks_only: build"
assert_not_contains "all" "$reply" "tasks_only: NO group 'all'"

run_helper _devsm_tests
reply="${(j: :)CAPTURED}"
assert_contains "unit" "$reply" "tests: unit"
assert_contains "integration" "$reply" "tests: integration"

run_helper _devsm_kinds
reply="${(j: :)CAPTURED}"
assert_contains "service" "$reply" "kinds: service"
assert_contains "action" "$reply" "kinds: action"
assert_contains "test" "$reply" "kinds: test"

run_helper _devsm_functions
reply="${(j: :)CAPTURED}"
assert_contains "restart_api" "$reply" "functions: restart_api"

run_helper _devsm_test_filters
reply="${(j: :)CAPTURED}"
assert_contains "unit" "$reply" "test_filters: 'unit'"
assert_contains "+fast" "$reply" "test_filters: '+fast'"
assert_contains "-slow" "$reply" "test_filters: '-slow'"

# vars_only inspects $words: simulate `devsm start deploy <cursor>`
words=(deploy)
CURRENT=2
CAPTURED=()
_devsm_vars_only
reply="${(j: :)CAPTURED}"
assert_contains "--host=" "$reply" "vars_only(deploy): --host="
assert_contains "--port=" "$reply" "vars_only(deploy): --port="

# vars_only with --host already used
words=(deploy --host=localhost)
CURRENT=3
CAPTURED=()
_devsm_vars_only
reply="${(j: :)CAPTURED}"
assert_contains "--port=" "$reply" "vars_only(deploy w/--host): --port="
assert_not_contains "--host=" "$reply" "vars_only(deploy w/--host): --host= excluded"

run_helper _devsm_commands
reply="${(j: :)CAPTURED}"
assert_contains "run" "$reply" "commands: run"
assert_contains "completions" "$reply" "commands: completions"
assert_contains "status" "$reply" "commands: status"
assert_contains "build" "$reply" "commands also includes runnables: build"
assert_contains "all" "$reply" "commands also includes runnables: all"

run_helper _devsm_self_commands
reply="${(j: :)CAPTURED}"
assert_contains "server" "$reply" "self_commands: server"
assert_contains "validate" "$reply" "self_commands: validate"
assert_contains "complete" "$reply" "self_commands: complete"

# Namespace + shadowing: runnables emits 'action.run' and 'group.logs' even
# though their bare forms are shadowed (by the builtin 'run' / 'logs' command).
run_helper _devsm_runnables
reply="${(j: :)CAPTURED}"
assert_contains "action.build" "$reply" "namespaced: action.build"
assert_contains "action.run" "$reply" "namespaced: action.run (bare shadowed by builtin)"
assert_contains "group.all" "$reply" "namespaced: group.all"
assert_contains "group.logs" "$reply" "namespaced: group.logs"
assert_not_contains "run" "$reply" "shadow: bare 'run' suppressed in runnables (builtin shadow)"
assert_not_contains "logs" "$reply" "shadow: bare 'logs' suppressed in runnables (builtin shadow)"

print ""
print "$TEST_COUNT assertions, $TEST_FAILURES failures"
exit $TEST_FAILURES
