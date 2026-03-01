#!/usr/bin/env bash
# =============================================================================
# Benchmark 04: Item Triage (item-triage custom app)
#
# USE CASE: An agent produces a list of items that need individual review —
#           dependency updates, config changes, migration steps, etc. A human
#           reviews each item in a tabbed UI, adjusts priority, adds notes,
#           and marks reviewed or skipped. The agent receives the full report.
#
# TESTS:
#   - custom app (item-triage), complex nested data shape
#   - multi-item tabbed UI with per-item edit state
#   - bulk submit action carrying annotated array value
#   - submit_decisions action type
#   - all priority levels represented (High, Medium, Low, None)
#   - --simulate mode
#
# RUN:
#   bash benchmarks/04_security_findings_qa.sh [--simulate]
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"
SCRIPTS="$REPO_DIR/scripts"
SIMULATE=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --simulate) SIMULATE=true; shift ;;
        *) echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

log()  { echo "[bench-04] $*"; }
step() { echo ""; echo "── $* ──────────────────────────────────"; }
ok()   { echo "✓ $*"; }

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
    bash "$SCRIPTS/wait_for_action.sh" --timeout 600 --action-type submit --clear
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

step "Starting item-triage webview"
bash "$SCRIPTS/start_webview.sh" --app item-triage ${SIMULATE:+--no-browser}
log "Server started."

step "Writing items state (5 items across priority levels)"

python3 - <<'PYEOF' | bash "$SCRIPTS/write_state.sh"
import json, datetime
now = datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
state = {
    'version': 1,
    'status': 'pending_review',
    'updated_at': now,
    'title': 'Dependency Update Review \u2014 acme/api-service',
    'message': '5 dependency updates available. Review each item, adjust priority, add notes, then submit your decisions.',
    'data': {
        'items': [
            {
                'id': 'DEP-001',
                'title': 'Upgrade React from 18.2.0 to 19.1.0',
                'category': 'Frontend',
                'priority': 'High',
                'description': 'Major version upgrade with breaking changes. New concurrent features, updated hooks API, and removal of legacy context. Requires updating component lifecycle patterns across the app.',
                'details': 'Breaking changes:\n- React.createClass removed\n- String refs removed\n- Legacy context API removed\n- ReactDOM.render deprecated\n\nnpm audit: 0 vulnerabilities',
                'impact': 'High — breaks existing component patterns, needs migration guide',
                'recommendation': 'Schedule for next sprint. Create migration branch, update incrementally.',
                'notes': ''
            },
            {
                'id': 'DEP-002',
                'title': 'Update TypeScript from 5.3.2 to 5.7.3',
                'category': 'Tooling',
                'priority': 'Medium',
                'description': 'Minor version update with new type-checking features and performance improvements. No breaking changes expected.',
                'details': 'Changelog highlights:\n- Improved type narrowing\n- New satisfies operator enhancements\n- 15% faster incremental builds\n- New --noCheck flag for emit-only mode',
                'impact': 'Low — backward compatible, may catch new type errors',
                'recommendation': 'Safe to update immediately. Run type-check after upgrade.',
                'notes': ''
            },
            {
                'id': 'DEP-003',
                'title': 'Upgrade ESLint from 8.55.0 to 9.18.0',
                'category': 'Tooling',
                'priority': 'Medium',
                'description': 'Major version upgrade. ESLint 9 uses flat config by default and deprecates .eslintrc format. Requires config migration.',
                'details': 'Migration needed:\n- Convert .eslintrc.json to eslint.config.js\n- Update plugin imports to flat config format\n- Remove deprecated rules\n- Update CI scripts',
                'impact': 'Medium — config migration needed, but no code changes',
                'recommendation': 'Use eslint-config-migrate tool. Test in CI before merging.',
                'notes': ''
            },
            {
                'id': 'DEP-004',
                'title': 'Patch axios from 1.6.2 to 1.6.8',
                'category': 'Runtime',
                'priority': 'Low',
                'description': 'Patch release fixing minor bugs in request interceptors and improving timeout handling.',
                'details': 'Fixes:\n- Fixed race condition in request interceptors\n- Improved AbortController cleanup\n- Better error messages for timeout\n\nnpm audit: 0 vulnerabilities',
                'impact': 'None — bug fixes only, fully backward compatible',
                'recommendation': 'Safe to update immediately.',
                'notes': ''
            },
            {
                'id': 'DEP-005',
                'title': 'Update prettier from 3.1.0 to 3.4.2',
                'category': 'Tooling',
                'priority': 'None',
                'description': 'Minor formatter update with improved handling of JSX, CSS, and markdown formatting. May produce minor whitespace diffs across the codebase.',
                'details': 'Changes:\n- Improved JSX expression formatting\n- Better CSS grid alignment\n- Markdown table auto-formatting\n\nNote: will reformat ~40 files with whitespace changes',
                'impact': 'None functionally — cosmetic reformatting only',
                'recommendation': 'Update and run format in a dedicated commit to keep diffs clean.',
                'notes': ''
            }
        ]
    },
    'actions_requested': []
}
print(json.dumps(state))
PYEOF

log "State written. Waiting for reviewer to triage all 5 items and submit decisions..."

SIM_VALUE='[{"id":"DEP-001","title":"Upgrade React from 18.2.0 to 19.1.0","category":"Frontend","priority":"High","status":"reviewed","notes":"Schedule for Q2. Needs migration branch."},{"id":"DEP-002","title":"Update TypeScript from 5.3.2 to 5.7.3","category":"Tooling","priority":"Medium","status":"reviewed","notes":"Safe to merge now."},{"id":"DEP-003","title":"Upgrade ESLint from 8.55.0 to 9.18.0","category":"Tooling","priority":"Medium","status":"skipped","notes":"Defer to next quarter — config migration too large right now."},{"id":"DEP-004","title":"Patch axios from 1.6.2 to 1.6.8","category":"Runtime","priority":"Low","status":"reviewed","notes":"Merge immediately."},{"id":"DEP-005","title":"Update prettier from 3.1.0 to 3.4.2","category":"Tooling","priority":"None","status":"reviewed","notes":"Format commit needed."}]'

RESULT=$(wait_for_response "submit_decisions" "submit" "$SIM_VALUE")

ACTION_ID=$(parse_action_id "$RESULT")
log "Action received: $ACTION_ID"

# ── Parse the submitted decisions ────────────────────────────────────────────
step "Processing submitted decisions"

python3 - <<'PYEOF' | bash "$SCRIPTS/write_state.sh"
import json, datetime
now = datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
print(json.dumps({
    'version': 2,
    'status': 'processing',
    'updated_at': now,
    'title': 'Processing Decisions...',
    'message': 'Agent is applying your update decisions.',
    'data': {},
    'actions_requested': []
}))
PYEOF

REPORT_STATS=$(python3 - "$RESULT" <<'PYEOF'
import json, sys
data = json.loads(sys.argv[1])
report = data['actions'][0].get('value', [])
by_status = {}
for item in report:
    s = item.get('status', 'pending')
    by_status[s] = by_status.get(s, 0) + 1
total = len(report)
reviewed = by_status.get('reviewed', 0)
skipped = by_status.get('skipped', 0)
print(f'{total}|{reviewed}|{skipped}')
PYEOF
)

TOTAL=$(echo "$REPORT_STATS" | cut -d'|' -f1)
REVIEWED=$(echo "$REPORT_STATS" | cut -d'|' -f2)
SKIPPED=$(echo "$REPORT_STATS" | cut -d'|' -f3)

if [[ "$SIMULATE" == "true" ]]; then sleep 0.5; else sleep 1; fi

python3 - "$TOTAL" "$REVIEWED" "$SKIPPED" <<'PYEOF' | bash "$SCRIPTS/write_state.sh"
import json, datetime, sys
total, reviewed, skipped = sys.argv[1], sys.argv[2], sys.argv[3]
now = datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
content = (
    f'Total items:        {total}\n'
    f'Approved:           {reviewed}\n'
    f'Skipped:            {skipped}\n\n'
    'Changes will be applied in the next CI run.'
)
print(json.dumps({
    'version': 3,
    'status': 'completed',
    'updated_at': now,
    'title': 'Dependency Review Complete',
    'message': f'Decisions recorded. {reviewed}/{total} approved, {skipped} deferred.',
    'data': {
        'ui': {
            'sections': [
                {
                    'type': 'text',
                    'title': 'Review Summary',
                    'content': content
                }
            ]
        }
    },
    'actions_requested': []
}))
PYEOF

ok "Decisions processed: $TOTAL items, $REVIEWED approved, $SKIPPED skipped."

if [[ "$SIMULATE" == "true" ]]; then sleep 0.5; else sleep 2; fi

bash "$SCRIPTS/close_webview.sh" --message "Dependency review complete."
bash "$SCRIPTS/stop_webview.sh"

echo ""
ok "Benchmark 04 complete: item triage with 5-item tabbed review exercised successfully."
