#!/usr/bin/env bash
# =============================================================================
# Benchmark 02: Code Review HITL (approval-review custom app)
#
# USE CASE: An AI coding agent proposes file changes and asks a developer to
#           review, approve, or reject with optional inline feedback.
#
# TESTS:
#   - custom app (approval-review), not the dynamic renderer
#   - unified diff rendering with colorized add/remove/hunk lines
#   - approve / reject / input (feedback textarea) action combo
#   - one-shot response model (buttons disabled after first response)
#   - completed state transition
#   - --simulate mode
#
# RUN:
#   bash benchmarks/02_code_review_hitl.sh [--simulate]
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

log()  { echo "[bench-02] $*"; }
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
    bash "$SCRIPTS/wait_for_action.sh" --timeout 300 --clear
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

step "Starting approval-review webview"
bash "$SCRIPTS/start_webview.sh" --app approval-review ${SIMULATE:+--no-browser}
log "Server started."

step "Writing state with 3 file diffs"

python3 - <<'PYEOF' | bash "$SCRIPTS/write_state.sh"
import json, datetime

now = datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')

diff_auth = """\
--- a/src/auth/middleware.py
+++ b/src/auth/middleware.py
@@ -1,12 +1,18 @@
 import jwt
-import time
+import time
+import hmac
+import hashlib
 from functools import wraps
 from flask import request, jsonify, g

-JWT_SECRET = "hardcoded-secret-change-me"
-JWT_ALGO   = "HS256"
+from config import settings
+
+JWT_SECRET = settings.JWT_SECRET
+JWT_ALGO   = settings.JWT_ALGO
+CSRF_KEY   = settings.CSRF_SECRET_KEY

 def require_auth(f):
     @wraps(f)
     def decorated(*args, **kwargs):
-        token = request.headers.get("Authorization", "").replace("Bearer ", "")
+        auth_hdr = request.headers.get("Authorization", "")
+        if not auth_hdr.startswith("Bearer "):
+            return jsonify({"error": "Missing or malformed Authorization header"}), 401
+        token = auth_hdr[7:]
         if not token:
             return jsonify({"error": "No token"}), 401
         try:
@@ -14,6 +20,12 @@ def require_auth(f):
         except jwt.ExpiredSignatureError:
             return jsonify({"error": "Token expired"}), 401
         except jwt.InvalidTokenError:
             return jsonify({"error": "Invalid token"}), 401
+
+        # CSRF double-submit cookie validation for state-mutating methods
+        if request.method in ("POST", "PUT", "DELETE", "PATCH"):
+            cookie = request.cookies.get("csrf_token", "")
+            header = request.headers.get("X-CSRF-Token", "")
+            if not hmac.compare_digest(cookie, header):
+                return jsonify({"error": "CSRF token mismatch"}), 403
         return f(*args, **kwargs)
     return decorated"""

diff_users = """\
--- a/src/users/routes.py
+++ b/src/users/routes.py
@@ -8,14 +8,22 @@
 from .models import User
 from .schemas import UserSchema

+MAX_PAGE_SIZE = 100
+
 @users_bp.route("/users", methods=["GET"])
 @require_auth
 def list_users():
-    users = User.query.all()
+    page     = max(1, request.args.get("page", 1, type=int))
+    per_page = min(request.args.get("per_page", 20, type=int), MAX_PAGE_SIZE)
+    users    = User.query.paginate(page=page, per_page=per_page, error_out=False)
     schema = UserSchema(many=True)
-    return jsonify(schema.dump(users))
+    return jsonify({
+        "items": schema.dump(users.items),
+        "page": page,
+        "per_page": per_page,
+        "total": users.total,
+        "pages": users.pages,
+    })

 @users_bp.route("/users/<int:user_id>", methods=["DELETE"])
 @require_auth
 def delete_user(user_id):
-    user = User.query.get(user_id)
-    if not user:
-        abort(404)
-    db.session.delete(user)
-    db.session.commit()
-    return "", 204
+    user = User.query.get_or_404(user_id)
+    if user.id == g.current_user.id:
+        return jsonify({"error": "Cannot delete your own account"}), 400
+    db.session.delete(user)
+    db.session.commit()
+    return "", 204"""

diff_tests = """\
--- a/tests/test_auth.py
+++ b/tests/test_auth.py
@@ -0,0 +1,38 @@
+import pytest
+from app import create_app
+from models import db, User
+
+@pytest.fixture
+def app():
+    app = create_app({"TESTING": True, "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:"})
+    with app.app_context():
+        db.create_all()
+        yield app
+        db.drop_all()
+
+@pytest.fixture
+def client(app):
+    return app.test_client()
+
+def test_missing_auth_header(client):
+    resp = client.get("/users")
+    assert resp.status_code == 401
+    assert "Missing or malformed" in resp.json["error"]
+
+def test_expired_token_rejected(client, expired_token):
+    resp = client.get("/users", headers={"Authorization": f"Bearer {expired_token}"})
+    assert resp.status_code == 401
+    assert resp.json["error"] == "Token expired"
+
+def test_csrf_required_on_mutation(client, valid_token):
+    resp = client.delete("/users/1", headers={"Authorization": f"Bearer {valid_token}"})
+    assert resp.status_code == 403
+    assert "CSRF" in resp.json["error"]
+
+def test_list_users_pagination(client, valid_token, csrf_header):
+    resp = client.get(
+        "/users?page=2&per_page=10",
+        headers={"Authorization": f"Bearer {valid_token}", **csrf_header}
+    )
+    assert resp.status_code == 200
+    assert "items" in resp.json
+    assert resp.json["per_page"] == 10"""

state = {
    'version': 1,
    'status': 'pending_review',
    'updated_at': now,
    'title': 'Review: Security & Pagination Hardening',
    'message': 'The agent proposes the following changes to harden authentication and add pagination to the users API. Please review each diff and approve or request changes.',
    'data': {
        'files_changed': [
            {
                'path': 'src/auth/middleware.py',
                'summary': 'Remove hardcoded secret, add CSRF double-submit validation',
                'diff': diff_auth
            },
            {
                'path': 'src/users/routes.py',
                'summary': 'Add pagination to list_users, prevent self-deletion',
                'diff': diff_users
            },
            {
                'path': 'tests/test_auth.py',
                'summary': 'New test suite covering auth, CSRF, and pagination',
                'diff': diff_tests
            }
        ],
        'total_files': 3,
        'total_lines_added': 56,
        'total_lines_removed': 14
    },
    'actions_requested': [
        {'id': 'approve', 'type': 'approve', 'label': 'Approve All Changes', 'description': 'Accept and apply all proposed changes'},
        {'id': 'reject', 'type': 'reject', 'label': 'Request Changes', 'description': 'Ask the agent to revise'},
        {'id': 'feedback', 'type': 'input', 'label': 'Feedback (optional)', 'required': False, 'description': 'Leave a comment for the agent'}
    ]
}
print(json.dumps(state))
PYEOF

log "State written. Waiting for user review..."

RESULT=$(wait_for_response "approve" "approve" "true")

ACTION=$(parse_action_id "$RESULT")
log "User action: $ACTION"

# ── Agent responds to decision ──────────────────────────────────────────────
if [[ "$ACTION" == "approve" ]]; then
    step "Applying approved changes"

    python3 - <<'PYEOF' | bash "$SCRIPTS/write_state.sh"
import json, datetime
now = datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
print(json.dumps({
    'version': 2,
    'status': 'processing',
    'updated_at': now,
    'title': 'Applying Changes...',
    'message': 'Writing files, running tests, and committing.',
    'data': {},
    'actions_requested': []
}))
PYEOF

    if [[ "$SIMULATE" == "true" ]]; then sleep 0.5; else sleep 2; fi

    python3 - <<'PYEOF' | bash "$SCRIPTS/write_state.sh"
import json, datetime
now = datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
print(json.dumps({
    'version': 3,
    'status': 'completed',
    'updated_at': now,
    'title': 'Changes Applied',
    'message': '3 files modified. Tests passing (47/47). Committed as feat/security-hardening.',
    'data': {},
    'actions_requested': []
}))
PYEOF
    ok "Changes approved and applied."

elif [[ "$ACTION" == "reject" ]]; then
    step "Handling rejection"

    python3 - <<'PYEOF' | bash "$SCRIPTS/write_state.sh"
import json, datetime
now = datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
print(json.dumps({
    'version': 2,
    'status': 'completed',
    'updated_at': now,
    'title': 'Changes Rejected',
    'message': 'The agent will revise based on feedback and propose updated changes.',
    'data': {},
    'actions_requested': []
}))
PYEOF
    ok "Changes rejected."
fi

if [[ "$SIMULATE" == "true" ]]; then sleep 0.5; else sleep 2; fi

bash "$SCRIPTS/close_webview.sh" --message "Review complete."
bash "$SCRIPTS/stop_webview.sh"

echo ""
ok "Benchmark 02 complete: code review HITL with 3-file diff exercised successfully."
