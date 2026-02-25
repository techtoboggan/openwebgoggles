#!/usr/bin/env bash
# =============================================================================
# Benchmark 01: Deployment Wizard (Multi-Step Form)
#
# USE CASE: A CI/CD agent that gathers deployment configuration from a developer
#           before executing a production deployment.
#
# TESTS:
#   - dynamic app, multi-step form wizard
#   - submit action value collection (multi-field)
#   - status transitions: waiting_input → waiting_input → pending_review → processing → completed
#   - --simulate mode for automated benchmarking
#
# RUN:
#   bash benchmarks/01_deployment_wizard.sh [--simulate]
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

log()  { echo "[bench-01] $*"; }
step() { echo ""; echo "── $* ──────────────────────────────────"; }
ok()   { echo "✓ $*"; }

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

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

parse_action_value() {
    # $1 = JSON string
    python3 - "$1" <<'PYEOF'
import json, sys
data = json.loads(sys.argv[1])
if data.get('actions'):
    v = data['actions'][0].get('value', {})
    print(json.dumps(v) if isinstance(v, dict) else str(v))
else:
    print('{}')
PYEOF
}

simulate_action() {
    # Injects action into actions.json; all output goes to stderr to avoid
    # polluting the captured JSON that wait_for_response() returns.
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
    # Returns JSON from wait_for_action.sh. In simulate mode, injects first.
    # simulate_action output goes to stderr so it does NOT contaminate $RESP.
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

# ── Step 1: Environment & version ──────────────────────────────────────────
step "Step 1/3: Gather deploy config"

python3 - <<'PYEOF' | bash "$SCRIPTS/write_state.sh"
import json, datetime
now = datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
state = {
    'version': 1,
    'status': 'waiting_input',
    'updated_at': now,
    'title': 'New Deployment \u2014 Step 1 of 3',
    'message': 'Select the target environment and Docker image tag to deploy.',
    'data': {
        'ui': {
            'sections': [
                {
                    'type': 'text',
                    'title': 'Current Production',
                    'content': 'Running: api:v2.3.1  \u2022  Region: us-east-1  \u2022  Replicas: 3  \u2022  Last deploy: 2h ago'
                },
                {
                    'type': 'form',
                    'title': 'Deployment Settings',
                    'columns': 2,
                    'fields': [
                        {
                            'key': 'environment',
                            'label': 'Target Environment',
                            'type': 'select',
                            'options': ['staging', 'production', 'canary'],
                            'value': 'staging'
                        },
                        {
                            'key': 'image_tag',
                            'label': 'Docker Image Tag',
                            'type': 'text',
                            'value': 'v2.4.0',
                            'placeholder': 'e.g. v2.4.0 or sha-abc1234'
                        },
                        {
                            'key': 'replicas',
                            'label': 'Replica Count',
                            'type': 'number',
                            'value': 3,
                            'min': 1,
                            'max': 20
                        },
                        {
                            'key': 'region',
                            'label': 'AWS Region',
                            'type': 'select',
                            'options': ['us-east-1', 'us-west-2', 'eu-west-1', 'ap-southeast-1'],
                            'value': 'us-east-1'
                        }
                    ],
                    'actions': [
                        {'id': 'next-step1', 'type': 'submit', 'label': 'Next \u2192', 'style': 'primary'},
                        {'id': 'cancel', 'type': 'reject', 'label': 'Cancel', 'style': 'ghost'}
                    ]
                }
            ]
        }
    },
    'actions_requested': []
}
print(json.dumps(state))
PYEOF

RESP1=$(wait_for_response "next-step1" "submit" \
    '{"environment":"production","image_tag":"v2.4.0","replicas":3,"region":"us-east-1"}')

ACTION1=$(parse_action_id "$RESP1")
if [[ "$ACTION1" == "cancel" ]]; then
    log "User cancelled at step 1."
    bash "$SCRIPTS/stop_webview.sh"
    exit 0
fi

VALS1=$(parse_action_value "$RESP1")
log "Step 1 values: $VALS1"

ENV=$(python3 - "$VALS1" <<'PYEOF'
import json, sys
print(json.loads(sys.argv[1]).get('environment', 'staging'))
PYEOF
)
TAG=$(python3 - "$VALS1" <<'PYEOF'
import json, sys
print(json.loads(sys.argv[1]).get('image_tag', 'latest'))
PYEOF
)
REPLICAS=$(python3 - "$VALS1" <<'PYEOF'
import json, sys
print(json.loads(sys.argv[1]).get('replicas', 1))
PYEOF
)
REGION=$(python3 - "$VALS1" <<'PYEOF'
import json, sys
print(json.loads(sys.argv[1]).get('region', 'us-east-1'))
PYEOF
)

ok "Step 1: env=$ENV tag=$TAG replicas=$REPLICAS region=$REGION"

# ── Step 2: Advanced options ────────────────────────────────────────────────
step "Step 2/3: Advanced options"

python3 - <<'PYEOF' | bash "$SCRIPTS/write_state.sh"
import json, datetime
now = datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
state = {
    'version': 2,
    'status': 'waiting_input',
    'updated_at': now,
    'title': 'New Deployment \u2014 Step 2 of 3',
    'message': 'Configure rollout strategy and health check parameters.',
    'data': {
        'ui': {
            'sections': [
                {
                    'type': 'form',
                    'title': 'Rollout Strategy',
                    'columns': 2,
                    'fields': [
                        {
                            'key': 'strategy',
                            'label': 'Deployment Strategy',
                            'type': 'select',
                            'options': ['rolling', 'blue-green', 'canary'],
                            'value': 'rolling'
                        },
                        {
                            'key': 'max_surge',
                            'label': 'Max Surge (%)',
                            'type': 'number',
                            'value': 25,
                            'min': 0,
                            'max': 100
                        },
                        {
                            'key': 'health_check_path',
                            'label': 'Health Check Path',
                            'type': 'text',
                            'value': '/health',
                            'placeholder': '/health'
                        },
                        {
                            'key': 'timeout_secs',
                            'label': 'Rollout Timeout (s)',
                            'type': 'number',
                            'value': 300,
                            'min': 60,
                            'max': 3600
                        },
                        {
                            'key': 'rollback_on_fail',
                            'label': 'Auto-rollback on failure',
                            'type': 'checkbox',
                            'value': True
                        },
                        {
                            'key': 'notify_slack',
                            'label': 'Notify #deploys on Slack',
                            'type': 'checkbox',
                            'value': True
                        }
                    ],
                    'actions': [
                        {'id': 'back', 'type': 'reject', 'label': '\u2190 Back', 'style': 'ghost'},
                        {'id': 'next-step2', 'type': 'submit', 'label': 'Review \u2192', 'style': 'primary'}
                    ]
                }
            ]
        }
    },
    'actions_requested': []
}
print(json.dumps(state))
PYEOF

RESP2=$(wait_for_response "next-step2" "submit" \
    '{"strategy":"rolling","max_surge":25,"health_check_path":"/health","timeout_secs":300,"rollback_on_fail":true,"notify_slack":true}')

VALS2=$(parse_action_value "$RESP2")
log "Step 2 values: $VALS2"

STRATEGY=$(python3 - "$VALS2" <<'PYEOF'
import json, sys
print(json.loads(sys.argv[1]).get('strategy', 'rolling'))
PYEOF
)
ROLLBACK=$(python3 - "$VALS2" <<'PYEOF'
import json, sys
print(json.loads(sys.argv[1]).get('rollback_on_fail', True))
PYEOF
)

ok "Step 2: strategy=$STRATEGY rollback=$ROLLBACK"

# ── Step 3: Review & confirm ─────────────────────────────────────────────────
step "Step 3/3: Review summary and confirm"

python3 - "$ENV" "$TAG" "$REPLICAS" "$REGION" "$STRATEGY" "$ROLLBACK" <<'PYEOF' | bash "$SCRIPTS/write_state.sh"
import json, datetime, sys
env, tag, replicas, region, strategy, rollback = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5], sys.argv[6]
now = datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
content = (
    f'Environment: {env}\n'
    f'Image Tag:   {tag}\n'
    f'Replicas:    {replicas}\n'
    f'Region:      {region}\n'
    f'Strategy:    {strategy}\n'
    f'Rollback:    {rollback}\n\n'
    'Estimated downtime: 0s (rolling deploy)\n'
    'Estimated duration: ~4 minutes'
)
state = {
    'version': 3,
    'status': 'pending_review',
    'updated_at': now,
    'title': 'Confirm Deployment',
    'message': 'Review the complete deployment plan. This will deploy to PRODUCTION.',
    'data': {
        'ui': {
            'sections': [
                {
                    'type': 'text',
                    'title': '\u26a0 Deployment Summary',
                    'content': content
                },
                {
                    'type': 'form',
                    'title': 'Confirmation',
                    'columns': 1,
                    'fields': [
                        {
                            'key': 'confirm_env',
                            'label': 'Type the environment name to confirm',
                            'type': 'text',
                            'placeholder': 'production'
                        }
                    ],
                    'actions': [
                        {'id': 'deploy-confirmed', 'type': 'submit', 'label': f'Deploy to {env}', 'style': 'danger'},
                        {'id': 'cancel-final', 'type': 'reject', 'label': 'Cancel', 'style': 'ghost'}
                    ]
                }
            ]
        }
    },
    'actions_requested': []
}
print(json.dumps(state))
PYEOF

RESP3=$(wait_for_response "deploy-confirmed" "submit" '{"confirm_env":"production"}')

ACTION3=$(parse_action_id "$RESP3")
if [[ "$ACTION3" == "cancel-final" ]]; then
    log "Deployment cancelled at confirmation step."
    python3 - <<'PYEOF' | bash "$SCRIPTS/write_state.sh"
import json, datetime
now = datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
print(json.dumps({'version': 4, 'status': 'completed', 'updated_at': now,
    'title': 'Deployment Cancelled', 'message': 'No changes were made.',
    'data': {}, 'actions_requested': []}))
PYEOF
    sleep 2
    bash "$SCRIPTS/close_webview.sh" --message "Deployment cancelled."
    bash "$SCRIPTS/stop_webview.sh"
    exit 0
fi

CONFIRM_VAL=$(parse_action_value "$RESP3")
ok "Step 3: confirmed — values=$CONFIRM_VAL"

# ── Processing ───────────────────────────────────────────────────────────────
step "Executing deployment"

python3 - "$TAG" "$ENV" "$REPLICAS" "$REGION" <<'PYEOF' | bash "$SCRIPTS/write_state.sh"
import json, datetime, sys
tag, env, replicas, region = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
now = datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
print(json.dumps({
    'version': 4,
    'status': 'processing',
    'updated_at': now,
    'title': f'Deploying {tag} to {env}...',
    'message': f'Rolling out {replicas} replica(s) in {region}. Do not close this window.',
    'data': {},
    'actions_requested': []
}))
PYEOF

if [[ "$SIMULATE" == "true" ]]; then
    sleep 1
else
    log "Running deployment (sleeping 3s to simulate work)..."
    sleep 3
fi

ok "Deployment completed."

# ── Completion ───────────────────────────────────────────────────────────────
step "Reporting completion"

python3 - "$TAG" "$ENV" "$REPLICAS" "$REGION" <<'PYEOF' | bash "$SCRIPTS/write_state.sh"
import json, datetime, sys
tag, env, replicas, region = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
now = datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
content = (
    f'Image: api:{tag}\n'
    f'Environment: {env}\n'
    f'Replicas: {replicas}/{replicas} healthy\n'
    f'Region: {region}\n'
    'Duration: 3m 42s'
)
print(json.dumps({
    'version': 5,
    'status': 'completed',
    'updated_at': now,
    'title': 'Deployment Successful',
    'message': f'{tag} is now live in {env} ({replicas} replicas in {region}). Health checks passing.',
    'data': {
        'ui': {
            'sections': [
                {
                    'type': 'text',
                    'title': '\u2713 Deployed',
                    'content': content
                }
            ]
        }
    },
    'actions_requested': []
}))
PYEOF

if [[ "$SIMULATE" == "true" ]]; then
    sleep 0.5
else
    sleep 2
fi

bash "$SCRIPTS/close_webview.sh" --message "Deployment complete. Window will close."
bash "$SCRIPTS/stop_webview.sh"

echo ""
ok "Benchmark 01 complete: 3-step deployment wizard exercised successfully."
