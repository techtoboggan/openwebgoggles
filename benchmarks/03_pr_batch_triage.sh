#!/usr/bin/env bash
# =============================================================================
# Benchmark 03: PR Batch Triage (Items List with Per-Item Actions)
#
# USE CASE: An agent has scanned a repo's open PRs and needs a human to triage
#           them — merge, hold, or close each one — before the agent acts.
#
# TESTS:
#   - dynamic app, items section with per-item action buttons
#   - non-blocking polling pattern (agent checks while doing other work)
#   - multi-action accumulation (multiple items, one action each)
#   - processing state while agent executes per-item decisions
#   - batch-results summary at completion
#   - --simulate mode
#
# RUN:
#   bash benchmarks/03_pr_batch_triage.sh [--simulate]
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

log()  { echo "[bench-03] $*"; }
step() { echo ""; echo "── $* ──────────────────────────────────"; }
ok()   { echo "✓ $*"; }

simulate_actions() {
    # All output goes to stderr so it does not pollute captured variables
    python3 - <<'PYEOF' >&2
import json, uuid, datetime

actions = []
items = [
    ('merge-pr-142', 'approve'),
    ('hold-pr-138',  'custom'),
    ('merge-pr-135', 'approve'),
    ('close-pr-129', 'reject'),
    ('merge-pr-127', 'approve'),
]
for action_id, action_type in items:
    actions.append({
        'id': str(uuid.uuid4()),
        'action_id': action_id,
        'type': action_type,
        'timestamp': datetime.datetime.utcnow().isoformat() + 'Z',
        'value': True if action_type == 'approve' else (False if action_type == 'reject' else 'hold')
    })

with open('.opencode/webview/actions.json', 'w') as f:
    json.dump({'version': len(actions), 'actions': actions}, f, indent=2)

print(f'[sim] injected {len(actions)} actions', flush=True)
PYEOF
}

# Parse a single action object JSON (passed as argument) and extract a field
get_action_field() {
    # $1 = action JSON string, $2 = field name
    python3 - "$1" "$2" <<'PYEOF'
import json, sys
d = json.loads(sys.argv[1])
print(d.get(sys.argv[2], ''))
PYEOF
}

# Parse actions.json content (passed as argument) and print each action as one JSON per line
print_actions() {
    # $1 = full actions.json JSON string
    python3 - "$1" <<'PYEOF'
import json, sys
data = json.loads(sys.argv[1])
for a in data.get('actions', []):
    print(json.dumps(a))
PYEOF
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

step "Starting dynamic webview"
bash "$SCRIPTS/start_webview.sh" --app dynamic ${SIMULATE:+--no-browser}
log "Server started."

step "Writing PR triage list state"

python3 - <<'PYEOF' | bash "$SCRIPTS/write_state.sh"
import json, datetime
now = datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
state = {
    'version': 1,
    'status': 'pending_review',
    'updated_at': now,
    'title': 'Open PRs \u2014 Triage Required',
    'message': 'The agent has analysed 5 open pull requests. Decide what to do with each one. You can action them in any order.',
    'data': {
        'ui': {
            'sections': [
                {
                    'type': 'text',
                    'title': 'Repository: acme/api-service',
                    'content': '5 PRs open  \u2022  3 passing CI  \u2022  1 failing CI  \u2022  1 draft\nBase branch: main  \u2022  Protected: yes'
                },
                {
                    'type': 'items',
                    'title': 'Pull Requests',
                    'items': [
                        {
                            'id': 'pr-142',
                            'title': 'feat: Add rate limiting middleware',
                            'subtitle': '#142 \u00b7 main \u2190 feat/rate-limit  \u2022  +312 -8  \u2022  \u2713 CI  \u2022  2 reviewers approved',
                            'actions': [
                                {'id': 'merge-pr-142', 'type': 'approve', 'label': 'Merge', 'style': 'success'},
                                {'id': 'hold-pr-142',  'type': 'custom',  'label': 'Hold',  'style': 'warning'},
                                {'id': 'close-pr-142', 'type': 'reject',  'label': 'Close', 'style': 'danger'}
                            ]
                        },
                        {
                            'id': 'pr-138',
                            'title': 'fix: Resolve N+1 query in user listing',
                            'subtitle': '#138 \u00b7 main \u2190 fix/n-plus-one  \u2022  +45 -67  \u2022  \u2713 CI  \u2022  1 reviewer approved',
                            'actions': [
                                {'id': 'merge-pr-138', 'type': 'approve', 'label': 'Merge', 'style': 'success'},
                                {'id': 'hold-pr-138',  'type': 'custom',  'label': 'Hold',  'style': 'warning'},
                                {'id': 'close-pr-138', 'type': 'reject',  'label': 'Close', 'style': 'danger'}
                            ]
                        },
                        {
                            'id': 'pr-135',
                            'title': 'chore: Upgrade dependencies (Nov 2025)',
                            'subtitle': '#135 \u00b7 main \u2190 chore/deps-nov25  \u2022  +0 -0 (lock only)  \u2022  \u2713 CI  \u2022  0 reviewers',
                            'actions': [
                                {'id': 'merge-pr-135', 'type': 'approve', 'label': 'Merge', 'style': 'success'},
                                {'id': 'hold-pr-135',  'type': 'custom',  'label': 'Hold',  'style': 'warning'},
                                {'id': 'close-pr-135', 'type': 'reject',  'label': 'Close', 'style': 'danger'}
                            ]
                        },
                        {
                            'id': 'pr-129',
                            'title': 'WIP: Refactor auth to OAuth2',
                            'subtitle': '#129 \u00b7 main \u2190 refactor/oauth2  \u2022  +1204 -892  \u2022  \u2717 CI failing  \u2022  DRAFT',
                            'actions': [
                                {'id': 'merge-pr-129', 'type': 'approve', 'label': 'Merge', 'style': 'success'},
                                {'id': 'hold-pr-129',  'type': 'custom',  'label': 'Hold',  'style': 'warning'},
                                {'id': 'close-pr-129', 'type': 'reject',  'label': 'Close', 'style': 'danger'}
                            ]
                        },
                        {
                            'id': 'pr-127',
                            'title': 'docs: Update API reference for v2 endpoints',
                            'subtitle': '#127 \u00b7 main \u2190 docs/v2-api-ref  \u2022  +88 -12  \u2022  \u2713 CI  \u2022  1 reviewer approved',
                            'actions': [
                                {'id': 'merge-pr-127', 'type': 'approve', 'label': 'Merge', 'style': 'success'},
                                {'id': 'hold-pr-127',  'type': 'custom',  'label': 'Hold',  'style': 'warning'},
                                {'id': 'close-pr-127', 'type': 'reject',  'label': 'Close', 'style': 'danger'}
                            ]
                        }
                    ]
                },
                {
                    'type': 'text',
                    'title': 'Note',
                    'content': 'You may action items in any order. The agent will act on each decision as you make it. Hold = defer to next triage cycle.'
                }
            ]
        }
    },
    'actions_requested': []
}
print(json.dumps(state))
PYEOF

log "State written. Using non-blocking polling — agent simulates other work between checks."

if [[ "$SIMULATE" == "true" ]]; then
    sleep 1
    simulate_actions
    sleep 0.3
fi

DECISIONS=()
MERGE_COUNT=0
HOLD_COUNT=0
CLOSE_COUNT=0
TOTAL_EXPECTED=5

step "Polling for triage decisions"
while [[ "${#DECISIONS[@]}" -lt "$TOTAL_EXPECTED" ]]; do
    COUNT=$(bash "$SCRIPTS/read_actions.sh" --count 2>/dev/null || echo "0")
    if [[ "$COUNT" -gt 0 ]]; then
        BATCH=$(bash "$SCRIPTS/read_actions.sh" --clear)
        # print_actions returns one JSON object per line; iterate over each line
        while IFS= read -r action_line; do
            [[ -z "$action_line" ]] && continue
            action_id=$(get_action_field "$action_line" "action_id")
            action_type=$(get_action_field "$action_line" "type")
            DECISIONS+=("$action_id:$action_type")
            if [[ "$action_type" == "approve" ]]; then MERGE_COUNT=$((MERGE_COUNT + 1)); fi
            if [[ "$action_type" == "custom"  ]]; then HOLD_COUNT=$((HOLD_COUNT + 1));   fi
            if [[ "$action_type" == "reject"  ]]; then CLOSE_COUNT=$((CLOSE_COUNT + 1)); fi
            log "Decision: $action_id → $action_type"
        done < <(print_actions "$BATCH")
    fi
    if [[ "${#DECISIONS[@]}" -lt "$TOTAL_EXPECTED" ]]; then
        [[ "$SIMULATE" == "true" ]] && break
        log "Waiting... (${#DECISIONS[@]}/$TOTAL_EXPECTED actioned)"
        sleep 2
    fi
done

ok "All decisions received: $MERGE_COUNT merge, $HOLD_COUNT hold, $CLOSE_COUNT close"

# ── Processing state while executing decisions ───────────────────────────────
step "Executing merge/close operations"

python3 - "$MERGE_COUNT" "$CLOSE_COUNT" "$HOLD_COUNT" <<'PYEOF' | bash "$SCRIPTS/write_state.sh"
import json, datetime, sys
merge, close, hold = sys.argv[1], sys.argv[2], sys.argv[3]
now = datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
print(json.dumps({
    'version': 2,
    'status': 'processing',
    'updated_at': now,
    'title': 'Executing Triage Decisions...',
    'message': f'Merging {merge} PR(s), closing {close} PR(s), deferring {hold} PR(s).',
    'data': {},
    'actions_requested': []
}))
PYEOF

if [[ "$SIMULATE" == "true" ]]; then sleep 0.5; else sleep 2; fi

# ── Completion summary ────────────────────────────────────────────────────────
step "Writing completion summary"

python3 - "$MERGE_COUNT" "$CLOSE_COUNT" "$HOLD_COUNT" <<'PYEOF' | bash "$SCRIPTS/write_state.sh"
import json, datetime, sys
merge, close, hold = sys.argv[1], sys.argv[2], sys.argv[3]
now = datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
content = (
    f'Merged:  {merge} PR(s)\n'
    f'Closed:  {close} PR(s)\n'
    f'Held:    {hold} PR(s)\n\n'
    'Next triage cycle: Tomorrow 09:00 UTC'
)
print(json.dumps({
    'version': 3,
    'status': 'completed',
    'updated_at': now,
    'title': 'PR Triage Complete',
    'message': f'{merge} merged, {close} closed, {hold} held for next cycle.',
    'data': {
        'ui': {
            'sections': [
                {
                    'type': 'text',
                    'title': 'Triage Results',
                    'content': content
                }
            ]
        }
    },
    'actions_requested': []
}))
PYEOF

if [[ "$SIMULATE" == "true" ]]; then sleep 0.5; else sleep 2; fi

bash "$SCRIPTS/close_webview.sh" --message "Triage complete."
bash "$SCRIPTS/stop_webview.sh"

echo ""
ok "Benchmark 03 complete: PR batch triage with non-blocking polling exercised successfully."
