#!/usr/bin/env bash
# =============================================================================
# Benchmark 05: Database Schema Migration (Progressive Status + Error Path)
#
# USE CASE: A DBA agent analyses a database migration script, shows the user
#           an impact analysis, asks for confirmation, then executes — with a
#           dry-run first. Demonstrates the error status path if dry-run fails.
#
# TESTS:
#   - dynamic app, text + actions sections (no form fields)
#   - progressive state updates showing live analysis results
#   - explicit confirm action (not a form, just a yes/no)
#   - error status path (dry-run fails → show error state → ask to retry or abort)
#   - --simulate mode with --force-error flag to exercise the error path
#
# RUN:
#   bash benchmarks/05_db_schema_migration.sh [--simulate] [--force-error]
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"
SCRIPTS="$REPO_DIR/scripts"
SIMULATE=false
FORCE_ERROR=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --simulate)    SIMULATE=true; shift ;;
        --force-error) FORCE_ERROR=true; shift ;;
        *) echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

log()  { echo "[bench-05] $*"; }
step() { echo ""; echo "── $* ──────────────────────────────────"; }
ok()   { echo "✓ $*"; }
err()  { echo "✗ $*"; }

parse_action_id() {
    # $1 = JSON string
    python3 - "$1" <<'PYEOF'
import json, sys
data = json.loads(sys.argv[1])
if data.get('actions'):
    print(data['actions'][0].get('action_id', ''))
else:
    print('')
PYEOF
}

simulate_action() {
    local action_id="$1"
    local action_type="$2"
    local value_json="$3"
    python3 - "$action_id" "$action_type" "$value_json" <<'PYEOF' >&2
import json, uuid, datetime, sys
action_id, action_type, value_json = sys.argv[1], sys.argv[2], sys.argv[3]
try:
    value = json.loads(value_json)
except Exception:
    value = value_json
actions = {
    'version': 1,
    'actions': [{
        'id': str(uuid.uuid4()),
        'action_id': action_id,
        'type': action_type,
        'timestamp': datetime.datetime.utcnow().isoformat() + 'Z',
        'value': value
    }]
}
with open('.openwebgoggles/actions.json', 'w') as f:
    json.dump(actions, f, indent=2)
print(f'[sim] injected action: {action_id} ({action_type})', flush=True)
PYEOF
}

wait_for_response() {
    local action_id="$1"
    local action_type="$2"
    local value_json="$3"
    if [[ "$SIMULATE" == "true" ]]; then
        sleep 1
        simulate_action "$action_id" "$action_type" "$value_json"
        sleep 0.3
    fi
    bash "$SCRIPTS/wait_for_action.sh" --timeout 300 --clear
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

step "Starting webview"
bash "$SCRIPTS/start_webview.sh" --app dynamic ${SIMULATE:+--no-browser}
log "Server started."

# ── Phase 1: Analysis (processing) ──────────────────────────────────────────
step "Phase 1: Analysing migration script"

python3 - <<'PYEOF' | bash "$SCRIPTS/write_state.sh"
import json, datetime
now = datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
print(json.dumps({
    'version': 1,
    'status': 'processing',
    'updated_at': now,
    'title': 'Analysing Migration: 0042_add_audit_log.sql',
    'message': 'Parsing SQL, checking foreign key constraints, estimating table lock duration...',
    'data': {},
    'actions_requested': []
}))
PYEOF

if [[ "$SIMULATE" == "true" ]]; then sleep 1; else sleep 3; fi

# ── Phase 2: Show analysis, ask to dry-run ──────────────────────────────────
step "Phase 2: Show analysis, request dry-run confirmation"

python3 - <<'PYEOF' | bash "$SCRIPTS/write_state.sh"
import json, datetime
now = datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
analysis = (
    'Migration: 0042_add_audit_log.sql\n'
    'Target:    prod-db-1 (PostgreSQL 15.4)\n\n'
    'Operations:\n'
    '  CREATE TABLE audit_log (8 columns, UUID pk)\n'
    '  CREATE INDEX idx_audit_log_user_id ON audit_log(user_id)\n'
    '  CREATE INDEX idx_audit_log_created_at ON audit_log(created_at)\n'
    '  ALTER TABLE users ADD COLUMN last_audit_at TIMESTAMPTZ DEFAULT NULL\n\n'
    'Risk Assessment:\n'
    '  Table lock on users:   ~200ms (estimated, 1.2M rows)\n'
    '  New table + indexes:   non-blocking\n'
    '  Reversible:            YES (down migration exists)\n'
    '  Estimated duration:    8-12 seconds\n\n'
    'Recommendation: Safe to proceed. Run dry-run first.'
)
state = {
    'version': 2,
    'status': 'pending_review',
    'updated_at': now,
    'title': 'Migration Analysis Ready',
    'message': 'Review the analysis below, then confirm whether to run a dry-run.',
    'data': {
        'ui': {
            'sections': [
                {
                    'type': 'text',
                    'title': 'Impact Analysis',
                    'content': analysis
                },
                {
                    'type': 'text',
                    'title': 'Actions',
                    'content': 'Choose an option below.',
                    'actions': [
                        {'id': 'confirm-dryrun', 'type': 'approve', 'label': 'Run Dry-Run', 'style': 'primary'},
                        {'id': 'abort',          'type': 'reject',  'label': 'Abort',       'style': 'ghost'}
                    ]
                }
            ]
        }
    },
    'actions_requested': []
}
print(json.dumps(state))
PYEOF

RESP2=$(wait_for_response "confirm-dryrun" "approve" "true")
ACTION2=$(parse_action_id "$RESP2")

if [[ "$ACTION2" == "abort" ]]; then
    log "User aborted before dry-run."
    python3 - <<'PYEOF' | bash "$SCRIPTS/write_state.sh"
import json, datetime
now = datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
print(json.dumps({'version': 3, 'status': 'completed', 'updated_at': now,
    'title': 'Migration Aborted', 'message': 'No changes were made to the database.',
    'data': {}, 'actions_requested': []}))
PYEOF
    sleep 2
    bash "$SCRIPTS/close_webview.sh" --message "Migration aborted."
    bash "$SCRIPTS/stop_webview.sh"
    exit 0
fi

ok "Dry-run confirmed."

# ── Phase 3: Dry-run ─────────────────────────────────────────────────────────
step "Phase 3: Running dry-run"

python3 - <<'PYEOF' | bash "$SCRIPTS/write_state.sh"
import json, datetime
now = datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
print(json.dumps({
    'version': 3,
    'status': 'processing',
    'updated_at': now,
    'title': 'Dry-Run in Progress...',
    'message': 'Executing migration in transaction (will be rolled back). Checking for errors.',
    'data': {},
    'actions_requested': []
}))
PYEOF

if [[ "$SIMULATE" == "true" ]]; then sleep 1; else sleep 2; fi

if [[ "$FORCE_ERROR" == "true" ]]; then
    # ── Error path ────────────────────────────────────────────────────────────
    err "Dry-run failed (--force-error). Showing error state."

    python3 - <<'PYEOF' | bash "$SCRIPTS/write_state.sh"
import json, datetime
now = datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
error_detail = (
    'Dry-run FAILED at statement 4 of 5:\n\n'
    '  ALTER TABLE users ADD COLUMN last_audit_at TIMESTAMPTZ DEFAULT NULL;\n\n'
    'Error: column "last_audit_at" of relation "users" already exists\n'
    'PG Error Code: 42701 (duplicate_column)\n\n'
    'The migration cannot proceed. The column was likely added manually.\n'
    'Options:\n'
    '  1. Retry: Update migration to use ADD COLUMN IF NOT EXISTS\n'
    '  2. Abort: Leave database unchanged'
)
state = {
    'version': 4,
    'status': 'error',
    'updated_at': now,
    'title': 'Dry-Run Failed',
    'message': 'The dry-run encountered an error. See details below.',
    'data': {
        'ui': {
            'sections': [
                {
                    'type': 'text',
                    'title': 'Error Details',
                    'content': error_detail
                },
                {
                    'type': 'text',
                    'title': 'Next Step',
                    'content': 'What would you like to do?',
                    'actions': [
                        {'id': 'retry',       'type': 'approve', 'label': 'Fix & Retry', 'style': 'warning'},
                        {'id': 'abort-error', 'type': 'reject',  'label': 'Abort',       'style': 'ghost'}
                    ]
                }
            ]
        }
    },
    'actions_requested': []
}
print(json.dumps(state))
PYEOF

    if [[ "$SIMULATE" == "true" ]]; then
        sleep 1
        simulate_action "abort-error" "reject" "false"
        sleep 0.3
    fi

    RESP_ERR=$(bash "$SCRIPTS/wait_for_action.sh" --timeout 300 --clear)
    ACTION_ERR=$(parse_action_id "$RESP_ERR")
    log "Error path decision: $ACTION_ERR"

    python3 - "$ACTION_ERR" <<'PYEOF' | bash "$SCRIPTS/write_state.sh"
import json, datetime, sys
action = sys.argv[1]
now = datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
if action == 'retry':
    msg = 'Agent will update the migration to use IF NOT EXISTS and retry.'
    title = 'Queued for Retry'
else:
    msg = 'Migration aborted. No changes were made to the database.'
    title = 'Migration Aborted'
print(json.dumps({'version': 5, 'status': 'completed', 'updated_at': now,
    'title': title, 'message': msg, 'data': {}, 'actions_requested': []}))
PYEOF

    if [[ "$SIMULATE" == "true" ]]; then sleep 0.5; else sleep 2; fi
    bash "$SCRIPTS/close_webview.sh" --message "Error path exercised."
    bash "$SCRIPTS/stop_webview.sh"
    echo ""
    ok "Benchmark 05 complete (--force-error path): error state and abort/retry loop exercised."
    exit 0
fi

# ── Dry-run success → confirm apply to prod ────────────────────────────────
step "Dry-run succeeded. Requesting production confirm."

python3 - <<'PYEOF' | bash "$SCRIPTS/write_state.sh"
import json, datetime
now = datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
dryrun_output = (
    'Dry-run SUCCESS (transaction rolled back)\n\n'
    'Statements executed: 5/5\n'
    'Errors: none\n'
    'Warnings: none\n'
    'Lock wait time: 0ms (no concurrent writes during test)\n'
    'Estimated prod lock: ~200ms\n\n'
    'The migration is safe to apply.'
)
state = {
    'version': 4,
    'status': 'pending_review',
    'updated_at': now,
    'title': 'Dry-Run Passed \u2014 Apply to Production?',
    'message': 'The dry-run completed without errors. Confirm to apply permanently.',
    'data': {
        'ui': {
            'sections': [
                {
                    'type': 'text',
                    'title': 'Dry-Run Output',
                    'content': dryrun_output
                },
                {
                    'type': 'text',
                    'title': 'Apply to Production',
                    'content': 'This will permanently alter prod-db-1. This action cannot be undone automatically.',
                    'actions': [
                        {'id': 'apply-prod', 'type': 'approve', 'label': 'Apply to Production', 'style': 'danger'},
                        {'id': 'abort-final','type': 'reject',  'label': 'Abort',               'style': 'ghost'}
                    ]
                }
            ]
        }
    },
    'actions_requested': []
}
print(json.dumps(state))
PYEOF

RESP4=$(wait_for_response "apply-prod" "approve" "true")
ACTION4=$(parse_action_id "$RESP4")

if [[ "$ACTION4" == "abort-final" ]]; then
    log "User aborted before production apply."
    python3 - <<'PYEOF' | bash "$SCRIPTS/write_state.sh"
import json, datetime
now = datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
print(json.dumps({'version': 5, 'status': 'completed', 'updated_at': now,
    'title': 'Migration Aborted', 'message': 'No changes were made to the database.',
    'data': {}, 'actions_requested': []}))
PYEOF
    sleep 2
    bash "$SCRIPTS/close_webview.sh" --message "Migration aborted."
    bash "$SCRIPTS/stop_webview.sh"
    exit 0
fi

ok "Production apply confirmed."

# ── Phase 4: Apply & complete ─────────────────────────────────────────────────
step "Phase 4: Applying migration to production"

python3 - <<'PYEOF' | bash "$SCRIPTS/write_state.sh"
import json, datetime
now = datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
print(json.dumps({
    'version': 5,
    'status': 'processing',
    'updated_at': now,
    'title': 'Applying Migration to prod-db-1...',
    'message': 'Running 0042_add_audit_log.sql in production. Do not close this window.',
    'data': {},
    'actions_requested': []
}))
PYEOF

if [[ "$SIMULATE" == "true" ]]; then sleep 1; else sleep 3; fi

python3 - <<'PYEOF' | bash "$SCRIPTS/write_state.sh"
import json, datetime
now = datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
summary = (
    'Migration: 0042_add_audit_log.sql\n'
    'Status:    APPLIED SUCCESSFULLY\n'
    'Duration:  9.3 seconds\n'
    'Statements: 5/5 committed\n'
    'Lock duration: 187ms on users table\n\n'
    'Schema version: 42\n'
    'Rollback available: yes (0042_add_audit_log_down.sql)'
)
print(json.dumps({
    'version': 6,
    'status': 'completed',
    'updated_at': now,
    'title': 'Migration Applied Successfully',
    'message': 'Schema version 42 is now active on prod-db-1.',
    'data': {
        'ui': {
            'sections': [
                {
                    'type': 'text',
                    'title': '\u2713 Migration Complete',
                    'content': summary
                }
            ]
        }
    },
    'actions_requested': []
}))
PYEOF

ok "Migration applied successfully."

if [[ "$SIMULATE" == "true" ]]; then sleep 0.5; else sleep 2; fi

bash "$SCRIPTS/close_webview.sh" --message "Migration complete."
bash "$SCRIPTS/stop_webview.sh"

echo ""
ok "Benchmark 05 complete: DB schema migration with progressive status exercised successfully."
