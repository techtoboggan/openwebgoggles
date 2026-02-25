#!/usr/bin/env bash
# =============================================================================
# Benchmark 04: Security Findings QA (security-qa custom app)
#
# USE CASE: A security scanning agent runs SAST/DAST tools and produces a set
#           of findings. A security engineer reviews each finding in the custom
#           tabbed UI, annotates severity, adds notes, and marks reviewed or
#           false-positive. The agent receives the full annotated report.
#
# TESTS:
#   - custom app (security-qa), complex nested data shape
#   - multi-finding tabbed UI with per-finding edit state
#   - bulk submit action carrying annotated array value
#   - submit_report action type
#   - all severity levels represented (Critical, High, Medium, Low, Info)
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

step "Starting security-qa webview"
bash "$SCRIPTS/start_webview.sh" --app security-qa ${SIMULATE:+--no-browser}
log "Server started."

step "Writing findings state (5 findings across severity levels)"

python3 - <<'PYEOF' | bash "$SCRIPTS/write_state.sh"
import json, datetime
now = datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
state = {
    'version': 1,
    'status': 'pending_review',
    'updated_at': now,
    'title': 'Security Assessment \u2014 acme/api-service',
    'message': 'SAST and DAST scan complete. 5 findings require analyst review. Mark each as reviewed or false positive, add notes, then submit the final report.',
    'data': {
        'findings': [
            {
                'id': 'FIND-001',
                'title': 'SQL Injection in login endpoint',
                'severity': 'Critical',
                'cvss_score': 9.8,
                'cwe_id': 'CWE-89',
                'affected_host': 'api.acme.com',
                'description': 'The login endpoint at POST /api/auth/login accepts a raw username parameter that is concatenated directly into a SQL query without parameterisation. An attacker can bypass authentication or extract arbitrary data.',
                'evidence': 'POST /api/auth/login\n{"username":"admin\'--","password":"x"}\nResponse: HTTP/1.1 200 OK {"token": "eyJ..."}',
                'recommendation': 'Use parameterised queries or an ORM. Never interpolate user input into SQL strings.',
                'notes': ''
            },
            {
                'id': 'FIND-002',
                'title': 'Missing HTTP Strict Transport Security (HSTS) header',
                'severity': 'Medium',
                'cvss_score': 5.3,
                'cwe_id': 'CWE-319',
                'affected_host': 'api.acme.com',
                'description': 'The API does not include the Strict-Transport-Security response header. Without HSTS, browsers may accept HTTP responses and are susceptible to SSL stripping attacks on the first connection.',
                'evidence': 'HTTP/1.1 200 OK\nContent-Type: application/json\n[HSTS header absent]',
                'recommendation': 'Add Strict-Transport-Security: max-age=31536000; includeSubDomains; preload to all HTTPS responses.',
                'notes': ''
            },
            {
                'id': 'FIND-003',
                'title': 'Exposed debug endpoint /admin/debug',
                'severity': 'High',
                'cvss_score': 7.5,
                'cwe_id': 'CWE-200',
                'affected_host': 'api.acme.com',
                'description': 'A debug endpoint at GET /admin/debug is accessible without authentication and returns internal system information including environment variables, database connection strings, and active request context.',
                'evidence': 'GET /admin/debug HTTP/1.1\nResponse: {"env": {"DATABASE_URL": "postgres://admin:s3cr3t@db:5432/prod", ...}}',
                'recommendation': 'Remove or disable the debug endpoint entirely in all non-development environments.',
                'notes': ''
            },
            {
                'id': 'FIND-004',
                'title': 'Outdated jQuery 2.x (CVE-2020-11023)',
                'severity': 'Low',
                'cvss_score': 3.7,
                'cwe_id': 'CWE-79',
                'affected_host': 'app.acme.com',
                'description': 'The web application loads jQuery 2.2.4 which is affected by CVE-2020-11023 — an XSS vulnerability in jQuery.htmlPrefilter() that can be triggered when passing HTML from untrusted sources.',
                'evidence': '<script src="/static/js/jquery-2.2.4.min.js"></script>\nNVD: CVE-2020-11023',
                'recommendation': 'Upgrade to jQuery 3.7.1 or later.',
                'notes': ''
            },
            {
                'id': 'FIND-005',
                'title': 'Missing rate limiting on authentication endpoint',
                'severity': 'Info',
                'cvss_score': 2.1,
                'cwe_id': 'CWE-307',
                'affected_host': 'api.acme.com',
                'description': 'The POST /api/auth/login endpoint does not implement rate limiting or account lockout. An attacker can make unlimited login attempts, facilitating brute-force or credential stuffing attacks.',
                'evidence': '1000 sequential login attempts completed without any 429 response or lockout.',
                'recommendation': 'Implement per-IP and per-username rate limiting (e.g. 10 attempts per minute). Add account lockout after N failures.',
                'notes': ''
            }
        ]
    },
    'actions_requested': []
}
print(json.dumps(state))
PYEOF

log "State written. Waiting for analyst to review all 5 findings and submit report..."

SIM_VALUE='[{"id":"FIND-001","title":"SQL Injection in login endpoint","severity":"Critical","cvss_score":9.8,"status":"reviewed","notes":"Confirmed. Login form param is unsanitized."},{"id":"FIND-002","title":"Missing HSTS header","severity":"Medium","cvss_score":5.3,"status":"false_positive","notes":"Infra handles HSTS at load balancer level."},{"id":"FIND-003","title":"Exposed debug endpoint /admin/debug","severity":"High","cvss_score":7.5,"status":"reviewed","notes":"Confirmed. Must be removed before prod release."},{"id":"FIND-004","title":"Outdated jQuery 2.x (CVE-2020-11023)","severity":"Low","cvss_score":3.7,"status":"reviewed","notes":"Upgrade to jQuery 3.7.1."},{"id":"FIND-005","title":"Missing rate limiting on /api/auth/login","severity":"Info","cvss_score":2.1,"status":"reviewed","notes":"Low priority but should be addressed."}]'

RESULT=$(wait_for_response "submit_report" "submit" "$SIM_VALUE")

ACTION_ID=$(parse_action_id "$RESULT")
log "Action received: $ACTION_ID"

# ── Parse the submitted report ────────────────────────────────────────────────
step "Processing submitted report"

python3 - <<'PYEOF' | bash "$SCRIPTS/write_state.sh"
import json, datetime
now = datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
print(json.dumps({
    'version': 2,
    'status': 'processing',
    'updated_at': now,
    'title': 'Processing Report...',
    'message': 'Agent is generating the final security report.',
    'data': {},
    'actions_requested': []
}))
PYEOF

REPORT_STATS=$(python3 - "$RESULT" <<'PYEOF'
import json, sys
data = json.loads(sys.argv[1])
report = data['actions'][0].get('value', [])
by_status = {}
for f in report:
    s = f.get('status', 'pending')
    by_status[s] = by_status.get(s, 0) + 1
total = len(report)
reviewed = by_status.get('reviewed', 0)
fp = by_status.get('false_positive', 0) + by_status.get('false-positive', 0)
print(f'{total}|{reviewed}|{fp}')
PYEOF
)

TOTAL=$(echo "$REPORT_STATS" | cut -d'|' -f1)
REVIEWED=$(echo "$REPORT_STATS" | cut -d'|' -f2)
FP=$(echo "$REPORT_STATS" | cut -d'|' -f3)

if [[ "$SIMULATE" == "true" ]]; then sleep 0.5; else sleep 1; fi

python3 - "$TOTAL" "$REVIEWED" "$FP" <<'PYEOF' | bash "$SCRIPTS/write_state.sh"
import json, datetime, sys
total, reviewed, fp = sys.argv[1], sys.argv[2], sys.argv[3]
now = datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
content = (
    f'Total findings:     {total}\n'
    f'Confirmed:          {reviewed}\n'
    f'False positives:    {fp}\n\n'
    'Report saved to: security-report.pdf'
)
print(json.dumps({
    'version': 3,
    'status': 'completed',
    'updated_at': now,
    'title': 'Security Assessment Complete',
    'message': f'Report generated. {reviewed}/{total} findings confirmed, {fp} marked false positive.',
    'data': {
        'ui': {
            'sections': [
                {
                    'type': 'text',
                    'title': 'Assessment Summary',
                    'content': content
                }
            ]
        }
    },
    'actions_requested': []
}))
PYEOF

ok "Report processed: $TOTAL findings, $REVIEWED confirmed, $FP false positives."

if [[ "$SIMULATE" == "true" ]]; then sleep 0.5; else sleep 2; fi

bash "$SCRIPTS/close_webview.sh" --message "Security assessment complete."
bash "$SCRIPTS/stop_webview.sh"

echo ""
ok "Benchmark 04 complete: security findings QA with 5-finding tabbed review exercised successfully."
