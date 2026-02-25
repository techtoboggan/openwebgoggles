#!/usr/bin/env bash
# =============================================================================
# Benchmark 06: ETL Data Pipeline Configuration
#
# USE CASE: A data engineering agent needs to configure a new ETL pipeline.
#           It presents a multi-section form covering source, destination,
#           and schedule settings — then confirms and shows a processing summary.
#
# TESTS:
#   - dynamic app, multi-section form (text + two 2-column forms + submit)
#   - all field types: text, textarea, number, select, checkbox, email
#   - single submit button at the bottom
#   - status transitions: waiting_input → processing → completed
#   - --simulate mode
#
# RUN:
#   bash benchmarks/06_data_pipeline_config.sh [--simulate]
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

log()  { echo "[bench-06] $*"; }
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

step "Writing pipeline config form"

python3 - <<'PYEOF' | bash "$SCRIPTS/write_state.sh"
import json, datetime
now = datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
state = {
    'version': 1,
    'status': 'waiting_input',
    'updated_at': now,
    'title': 'Configure ETL Pipeline',
    'message': 'Fill in the source, destination, and schedule settings for the new pipeline, then click Create Pipeline.',
    'data': {
        'ui': {
            'sections': [
                {
                    'type': 'text',
                    'title': 'About This Pipeline',
                    'content': (
                        'This pipeline will extract data from a PostgreSQL source, apply transformation rules, '
                        'and load it into the data warehouse on a scheduled cadence.\n\n'
                        'All fields marked with * are required. The pipeline will be created in a paused state '
                        'and must be manually enabled after review.'
                    )
                },
                {
                    'type': 'form',
                    'title': 'Source Configuration',
                    'columns': 2,
                    'fields': [
                        {
                            'key': 'source_name',
                            'label': 'Pipeline Name *',
                            'type': 'text',
                            'placeholder': 'e.g. crm-to-warehouse-daily',
                            'value': ''
                        },
                        {
                            'key': 'source_type',
                            'label': 'Source Type *',
                            'type': 'select',
                            'options': ['PostgreSQL', 'MySQL', 'MongoDB', 'S3', 'REST API', 'Kafka'],
                            'value': 'PostgreSQL'
                        },
                        {
                            'key': 'source_host',
                            'label': 'Source Host *',
                            'type': 'text',
                            'placeholder': 'db.internal.acme.com',
                            'value': ''
                        },
                        {
                            'key': 'source_port',
                            'label': 'Source Port',
                            'type': 'number',
                            'value': 5432,
                            'min': 1,
                            'max': 65535
                        },
                        {
                            'key': 'source_database',
                            'label': 'Database / Collection *',
                            'type': 'text',
                            'placeholder': 'production_crm',
                            'value': ''
                        },
                        {
                            'key': 'source_table',
                            'label': 'Table / Query *',
                            'type': 'text',
                            'placeholder': 'customers or SELECT ...',
                            'value': ''
                        },
                        {
                            'key': 'transform_sql',
                            'label': 'Transformation SQL (optional)',
                            'type': 'textarea',
                            'placeholder': 'SELECT id, name, email, created_at FROM customers WHERE deleted_at IS NULL',
                            'value': ''
                        },
                        {
                            'key': 'incremental',
                            'label': 'Incremental load (use watermark)',
                            'type': 'checkbox',
                            'value': True
                        }
                    ]
                },
                {
                    'type': 'form',
                    'title': 'Destination & Schedule',
                    'columns': 2,
                    'fields': [
                        {
                            'key': 'dest_type',
                            'label': 'Destination Type *',
                            'type': 'select',
                            'options': ['BigQuery', 'Snowflake', 'Redshift', 'ClickHouse', 'S3 Parquet'],
                            'value': 'BigQuery'
                        },
                        {
                            'key': 'dest_dataset',
                            'label': 'Destination Dataset / Schema *',
                            'type': 'text',
                            'placeholder': 'dwh_raw.crm',
                            'value': ''
                        },
                        {
                            'key': 'schedule',
                            'label': 'Schedule (cron) *',
                            'type': 'select',
                            'options': ['Every 15 min', 'Hourly', 'Every 6h', 'Daily 02:00 UTC', 'Weekly Sunday', 'Manual only'],
                            'value': 'Daily 02:00 UTC'
                        },
                        {
                            'key': 'max_retries',
                            'label': 'Max Retries on Failure',
                            'type': 'number',
                            'value': 3,
                            'min': 0,
                            'max': 10
                        },
                        {
                            'key': 'alert_email',
                            'label': 'Alert Email *',
                            'type': 'email',
                            'placeholder': 'data-team@acme.com',
                            'value': ''
                        },
                        {
                            'key': 'notify_on_success',
                            'label': 'Notify on success (not just failure)',
                            'type': 'checkbox',
                            'value': False
                        },
                        {
                            'key': 'notes',
                            'label': 'Notes / Description',
                            'type': 'textarea',
                            'placeholder': 'Describe the purpose of this pipeline...',
                            'value': ''
                        },
                        {
                            'key': 'enabled',
                            'label': 'Enable pipeline immediately after creation',
                            'type': 'checkbox',
                            'value': False
                        }
                    ],
                    'actions': [
                        {'id': 'create-pipeline', 'type': 'submit', 'label': 'Create Pipeline', 'style': 'primary'},
                        {'id': 'cancel',          'type': 'reject', 'label': 'Cancel',          'style': 'ghost'}
                    ]
                }
            ]
        }
    },
    'actions_requested': []
}
print(json.dumps(state))
PYEOF

log "Form written. Waiting for pipeline config submission..."

SIM_VALUE='{"source_name":"crm-to-warehouse-daily","source_type":"PostgreSQL","source_host":"db.internal.acme.com","source_port":5432,"source_database":"production_crm","source_table":"customers","transform_sql":"SELECT id, name, email, created_at FROM customers WHERE deleted_at IS NULL","incremental":true,"dest_type":"BigQuery","dest_dataset":"dwh_raw.crm","schedule":"Daily 02:00 UTC","max_retries":3,"alert_email":"data-team@acme.com","notify_on_success":false,"notes":"Daily sync of CRM customer records to the data warehouse for reporting.","enabled":false}'

RESP=$(wait_for_response "create-pipeline" "submit" "$SIM_VALUE")

ACTION=$(parse_action_id "$RESP")
if [[ "$ACTION" == "cancel" ]]; then
    log "User cancelled pipeline creation."
    python3 - <<'PYEOF' | bash "$SCRIPTS/write_state.sh"
import json, datetime
now = datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
print(json.dumps({'version': 2, 'status': 'completed', 'updated_at': now,
    'title': 'Cancelled', 'message': 'No pipeline was created.', 'data': {}, 'actions_requested': []}))
PYEOF
    sleep 2
    bash "$SCRIPTS/close_webview.sh" --message "Cancelled."
    bash "$SCRIPTS/stop_webview.sh"
    exit 0
fi

VALS=$(parse_action_value "$RESP")
log "Form values received."

PIPELINE_NAME=$(python3 - "$VALS" <<'PYEOF'
import json, sys
print(json.loads(sys.argv[1]).get('source_name', 'unnamed-pipeline'))
PYEOF
)
DEST_TYPE=$(python3 - "$VALS" <<'PYEOF'
import json, sys
print(json.loads(sys.argv[1]).get('dest_type', 'BigQuery'))
PYEOF
)
SCHEDULE=$(python3 - "$VALS" <<'PYEOF'
import json, sys
print(json.loads(sys.argv[1]).get('schedule', 'Daily 02:00 UTC'))
PYEOF
)
ALERT_EMAIL=$(python3 - "$VALS" <<'PYEOF'
import json, sys
print(json.loads(sys.argv[1]).get('alert_email', ''))
PYEOF
)

ok "Pipeline config: name=$PIPELINE_NAME dest=$DEST_TYPE schedule=$SCHEDULE"

# ── Processing ───────────────────────────────────────────────────────────────
step "Creating pipeline"

python3 - "$PIPELINE_NAME" <<'PYEOF' | bash "$SCRIPTS/write_state.sh"
import json, datetime, sys
name = sys.argv[1]
now = datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
print(json.dumps({
    'version': 2,
    'status': 'processing',
    'updated_at': now,
    'title': f'Creating Pipeline: {name}...',
    'message': 'Validating source connection, provisioning destination dataset, registering schedule...',
    'data': {},
    'actions_requested': []
}))
PYEOF

if [[ "$SIMULATE" == "true" ]]; then sleep 1; else sleep 3; fi

# ── Completion ───────────────────────────────────────────────────────────────
step "Reporting completion"

python3 - "$PIPELINE_NAME" "$DEST_TYPE" "$SCHEDULE" "$ALERT_EMAIL" <<'PYEOF' | bash "$SCRIPTS/write_state.sh"
import json, datetime, sys, uuid
name, dest, schedule, email = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
now = datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
pipeline_id = f'pipe-{str(uuid.uuid4())[:8]}'
summary = (
    f'Pipeline ID:    {pipeline_id}\n'
    f'Name:           {name}\n'
    f'Destination:    {dest}\n'
    f'Schedule:       {schedule}\n'
    f'Status:         PAUSED (enable when ready)\n'
    f'Alerts:         {email}\n\n'
    'Source connection: VERIFIED\n'
    'Destination dataset: PROVISIONED\n'
    'First run: will execute on next scheduled trigger after enabling'
)
print(json.dumps({
    'version': 3,
    'status': 'completed',
    'updated_at': now,
    'title': 'Pipeline Created Successfully',
    'message': f'Pipeline "{name}" has been created and is ready to enable.',
    'data': {
        'ui': {
            'sections': [
                {
                    'type': 'text',
                    'title': '\u2713 Pipeline Ready',
                    'content': summary
                }
            ]
        }
    },
    'actions_requested': []
}))
PYEOF

ok "Pipeline '$PIPELINE_NAME' created."

if [[ "$SIMULATE" == "true" ]]; then sleep 0.5; else sleep 2; fi

bash "$SCRIPTS/close_webview.sh" --message "Pipeline created."
bash "$SCRIPTS/stop_webview.sh"

echo ""
ok "Benchmark 06 complete: ETL pipeline config multi-section form exercised successfully."
