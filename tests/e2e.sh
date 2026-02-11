#!/usr/bin/env bash
#
# End-to-end test for the pipe CLI against a real server.
#
# Usage:
#   ./tests/e2e.sh [API_URL]
#
# Defaults to https://us-west-01-firestarter.pipenetwork.com
# Uses a temp directory for config and keypair — no pollution of real config.
#
set -euo pipefail

API="${1:-https://us-west-01-firestarter.pipenetwork.com}"

# Resolve binary: prefer release, fall back to debug
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
if [[ -x "$PROJECT_DIR/target/release/pipe" ]]; then
    PIPE="$PROJECT_DIR/target/release/pipe"
elif [[ -x "$PROJECT_DIR/target/debug/pipe" ]]; then
    PIPE="$PROJECT_DIR/target/debug/pipe"
else
    echo "FAIL: No pipe binary found. Run 'cargo build' first."
    exit 1
fi

# Temp directory for isolation — cleaned up on exit
TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

CONFIG="$TMPDIR/config.json"
KEYPAIR="$TMPDIR/wallet.json"

passed=0
failed=0
total=0

# ── Test helpers ──────────────────────────────────────────────

run_pipe() {
    "$PIPE" --api "$API" --config "$CONFIG" "$@"
}

assert_success() {
    local desc="$1"
    shift
    total=$((total + 1))
    local output
    if output=$(run_pipe "$@" 2>&1); then
        passed=$((passed + 1))
        echo "  PASS  $desc"
        echo "$output"  # return output for capture
    else
        failed=$((failed + 1))
        echo "  FAIL  $desc (exit=$?)"
        echo "        $output" >&2
        return 1
    fi
}

assert_output_contains() {
    local desc="$1"
    local pattern="$2"
    shift 2
    total=$((total + 1))
    local output
    if output=$(run_pipe "$@" 2>&1); then
        if echo "$output" | grep -qiE "$pattern"; then
            passed=$((passed + 1))
            echo "  PASS  $desc"
        else
            failed=$((failed + 1))
            echo "  FAIL  $desc — output missing pattern: $pattern"
            echo "        $output" >&2
        fi
    else
        failed=$((failed + 1))
        echo "  FAIL  $desc (exit=$?)"
        echo "        $output" >&2
    fi
}

assert_fails() {
    local desc="$1"
    shift
    total=$((total + 1))
    local output
    if output=$(run_pipe "$@" 2>&1); then
        failed=$((failed + 1))
        echo "  FAIL  $desc — expected failure but got success"
        echo "        $output" >&2
    else
        passed=$((passed + 1))
        echo "  PASS  $desc (correctly failed)"
    fi
}

# ── Tests ─────────────────────────────────────────────────────

echo ""
echo "pipe CLI e2e tests"
echo "  api:     $API"
echo "  binary:  $PIPE"
echo "  config:  $CONFIG"
echo "  keypair: $KEYPAIR"
echo ""

echo "── Phase 1: Pre-auth (should fail without credentials) ──"
assert_fails "profile without auth" profile
assert_fails "sessions without auth" sessions
assert_fails "credits-status without auth" credits-status

echo ""
echo "── Phase 2: Keypair generation ──"
assert_success "wallet-keygen" wallet-keygen --output "$KEYPAIR"

total=$((total + 1))
if [[ -f "$KEYPAIR" ]]; then
    passed=$((passed + 1))
    echo "  PASS  keypair file exists"
else
    failed=$((failed + 1))
    echo "  FAIL  keypair file not created"
fi

assert_fails "wallet-keygen refuses overwrite" wallet-keygen --output "$KEYPAIR"
assert_success "wallet-keygen --force overwrites" wallet-keygen --output "$KEYPAIR" --force

echo ""
echo "── Phase 3: Authentication (SIWS) ──"
assert_success "wallet-auth" wallet-auth --keypair "$KEYPAIR"

total=$((total + 1))
if [[ -f "$CONFIG" ]]; then
    passed=$((passed + 1))
    echo "  PASS  config file created after auth"
else
    failed=$((failed + 1))
    echo "  FAIL  config file not created after auth"
fi

echo ""
echo "── Phase 4: Authenticated commands ──"
assert_output_contains "profile shows user_id" "user.id" profile
assert_output_contains "profile shows wallet" "wallet" profile

assert_success "credits-status" credits-status
assert_success "usage (30d)" usage
assert_output_contains "usage shows period" "usage for period" usage --period 30d

assert_success "sessions list" sessions
assert_output_contains "sessions shows current" "current" sessions

echo ""
echo "── Phase 5: S3 key lifecycle ──"
KEY_OUTPUT=$(run_pipe s3-key-create 2>&1) || true
total=$((total + 1))
# Extract from "Access Key ID:     PIPExxxx" or "export AWS_ACCESS_KEY_ID=PIPExxxx"
ACCESS_KEY_ID=$(echo "$KEY_OUTPUT" | grep -i 'access.key.id' | grep -oE 'PIPE[a-zA-Z0-9]+' | head -1 || true)
if [[ -z "$ACCESS_KEY_ID" ]]; then
    ACCESS_KEY_ID=$(echo "$KEY_OUTPUT" | grep -oE 'AWS_ACCESS_KEY_ID=[^ ]+' | head -1 | cut -d= -f2 || true)
fi
if [[ -n "$ACCESS_KEY_ID" ]]; then
    passed=$((passed + 1))
    echo "  PASS  s3-key-create returned access key: $ACCESS_KEY_ID"
else
    failed=$((failed + 1))
    echo "  FAIL  s3-key-create — could not extract access key ID"
    echo "        $KEY_OUTPUT" >&2
fi

assert_output_contains "s3-key-list shows key" "$ACCESS_KEY_ID" s3-key-list

if [[ -n "$ACCESS_KEY_ID" ]]; then
    assert_success "s3-key-delete" s3-key-delete "$ACCESS_KEY_ID" --yes
fi

assert_success "s3-info" s3-info

echo ""
echo "── Phase 6: Config commands ──"
assert_success "config show" config show
assert_output_contains "config show displays API URL" "$API" config show

echo ""
echo "── Phase 7: Logout ──"
assert_success "logout" logout

# After logout, authenticated commands should fail
assert_fails "profile after logout" profile

echo ""
echo "════════════════════════════════════════════════════"
echo "  Results: $passed/$total passed, $failed failed"
echo "════════════════════════════════════════════════════"
echo ""

if [[ $failed -gt 0 ]]; then
    exit 1
fi
