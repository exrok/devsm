#!/bin/sh
# Common helpers for completion test scripts.
# Sourced by bash.test.sh / fish.test.fish / zsh.test.zsh runners.

set -eu

# Project root (this file lives at $REPO/tests/completions/harness.sh).
TESTS_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$TESTS_DIR/../.." && pwd)"

# Use the cargo-built debug binary. The test target enforces `require = [{ resource = "cargo-bin" }]`
# so the binary is fresh by the time we run.
TARGET_DIR="${CARGO_TARGET_DIR:-/tmp/rust-target}"
[ -d "$TARGET_DIR" ] || TARGET_DIR="$REPO_ROOT/target"
DEVSM_BIN="$TARGET_DIR/debug/devsm"

if [ ! -x "$DEVSM_BIN" ]; then
    echo "harness: $DEVSM_BIN not found; build devsm first (cargo build)" >&2
    exit 1
fi

# Tests must run with the fixture workspace as cwd so devsm.toml is found.
FIXTURE="$TESTS_DIR/workspace"
cd "$FIXTURE"

# Prepend the cargo-built directory to PATH so the completion scripts'
# unqualified `devsm self complete ...` invocations hit our binary.
PATH="$TARGET_DIR/debug:$PATH"
export PATH

# Disable daemon auto-spawn during completion (config is loaded from disk only).
DEVSM_NO_AUTO_SPAWN=1
export DEVSM_NO_AUTO_SPAWN

TEST_FAILURES=0
TEST_COUNT=0

# assert_contains "needle" "haystack" "label"
assert_contains() {
    TEST_COUNT=$((TEST_COUNT + 1))
    needle="$1"
    haystack="$2"
    label="$3"
    case " $haystack " in
        *" $needle "*)
            echo "  ok: $label"
            ;;
        *)
            TEST_FAILURES=$((TEST_FAILURES + 1))
            echo "  FAIL: $label" >&2
            echo "    expected to contain: [$needle]" >&2
            echo "    actual: [$haystack]" >&2
            ;;
    esac
}

# assert_not_contains "needle" "haystack" "label"
assert_not_contains() {
    TEST_COUNT=$((TEST_COUNT + 1))
    needle="$1"
    haystack="$2"
    label="$3"
    case " $haystack " in
        *" $needle "*)
            TEST_FAILURES=$((TEST_FAILURES + 1))
            echo "  FAIL: $label" >&2
            echo "    expected NOT to contain: [$needle]" >&2
            echo "    actual: [$haystack]" >&2
            ;;
        *)
            echo "  ok: $label"
            ;;
    esac
}

report_and_exit() {
    echo ""
    echo "$TEST_COUNT assertions, $TEST_FAILURES failures"
    if [ "$TEST_FAILURES" -gt 0 ]; then
        exit 1
    fi
    exit 0
}
