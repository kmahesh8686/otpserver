from flask import Flask, request, jsonify, redirect, url_for, session, render_template_string
from flask_cors import CORS
from datetime import datetime
import zoneinfo, time

app = Flask(__name__)
app.secret_key = "SUPERSECRETKEY"
CORS(app)

IST = zoneinfo.ZoneInfo("Asia/Kolkata")

# =========================
# Predefined Tokens
# =========================
PREDEFINED_TOKENS = ["km8686", "kmk8686", "km5630"]
token_passwords = {t: "12345678" for t in PREDEFINED_TOKENS}
ADMIN_PASSWORD = "12345678"

# Mobile caps
token_mobile_caps = {t: None for t in PREDEFINED_TOKENS}
token_processed_mobiles = {t: set() for t in PREDEFINED_TOKENS}

# =========================
# Storage
# =========================
mobile_groups = {t: {} for t in PREDEFINED_TOKENS}     # per-token mobile OTPs (sim_number -> list of entries)
vehicle_otps = {t: [] for t in PREDEFINED_TOKENS}      # vehicle OTPs (list of entries)
otp_data = {t: [] for t in PREDEFINED_TOKENS}          # retained history of deliveries
client_sessions = {t: {} for t in PREDEFINED_TOKENS}   # browser sessions keyed by (identifier, browser_id)
login_sessions = {t: {} for t in PREDEFINED_TOKENS}    # login detect

# =========================
# Helper
# =========================
def valid_token(token: str) -> bool:
    return token in PREDEFINED_TOKENS


# =========================
# RECEIVE OTP
# =========================
@app.route('/api/receive-otp', methods=['POST'])
def receive_otp():
    try:
        data = request.get_json(force=True)
        otp = (data.get('otp') or "").strip()
        token = (data.get('token') or "").strip()
        sim_number = (data.get('sim_number') or "").strip().upper()
        vehicle = (data.get('vehicle') or "").strip().upper()

        if not otp or not token:
            return jsonify({"status": "error", "message": "OTP and token required"}), 400
        if not valid_token(token):
            return jsonify({"status": "error", "message": "Invalid token"}), 403

        now_dt = datetime.now(IST)

        # Enforce mobile cap for mobiles only
        if not vehicle:
            if sim_number not in token_processed_mobiles[token]:
                cap = token_mobile_caps[token]
                if cap is not None and len(token_processed_mobiles[token]) >= cap:
                    entry = {
                        "otp": otp,
                        "token": token,
                        "sim_number": sim_number,
                        "timestamp": now_dt,
                        "removed_reason": "limit_exceeded"
                    }
                    otp_data[token].append(entry)
                    return jsonify({"status": "success"}), 200
                token_processed_mobiles[token].add(sim_number)

        entry = {
            "otp": otp,
            "token": token,
            "timestamp": now_dt
        }

        # VEHICLE OTP
        if vehicle:
            entry["vehicle"] = vehicle

            # store vehicle OTP
            vehicle_otps[token].append(entry.copy())

            # history store (raw arrival)
            otp_data[token].append(entry.copy())
            return jsonify({"status": "success"}), 200

        # MOBILE OTP
        sim_number = sim_number or "UNKNOWNSIM"
        entry["sim_number"] = sim_number

        # store in history (raw arrival)
        otp_data[token].append(entry.copy())

        # store in mobile group
        if sim_number not in mobile_groups[token]:
            mobile_groups[token][sim_number] = []
        mobile_groups[token][sim_number].append(entry.copy())

        return jsonify({"status": "success"}), 200

    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 400


# =========================
# GET LATEST OTP (Browser side)
# =========================
@app.route('/api/get-latest-otp', methods=['GET'])
def get_latest_otp():
    token = (request.args.get('token') or "").strip()
    sim_number = (request.args.get('sim_number') or "").strip().upper()
    vehicle = (request.args.get('vehicle') or "").strip().upper()
    browser_id = (request.args.get('browser_id') or "").strip()

    if not token or (not sim_number and not vehicle) or not browser_id:
        return jsonify({"status": "error", "message": "token + sim_number/vehicle + browser_id required"}), 400
    if not valid_token(token):
        return jsonify({"status": "error", "message": "Invalid token"}), 403

    identifier = sim_number if sim_number else vehicle

    now_ts = time.time()
    now_dt = datetime.now(IST)

    # Create/update session
    sess_key = (identifier, browser_id)
    if sess_key not in client_sessions[token]:
        client_sessions[token][sess_key] = {
            "first_request_ts": now_ts,
            "first_request_dt": now_dt,
            "last_request_ts": now_ts,
            "last_delivered_ts": 0   # timestamp of last OTP delivered to this browser-session
        }
    else:
        client_sessions[token][sess_key]["last_request_ts"] = now_ts

    sess = client_sessions[token][sess_key]
    # first_ts kept for compatibility but not used for delivery gating anymore
    first_ts = sess["first_request_ts"]

    # ========================
    # VEHICLE OTP POLLING
    # ========================
    if vehicle:
        # find OTPS for that vehicle that are newer than this session's last_delivered_ts
        new_otps = [
            o for o in vehicle_otps[token]
            if o["vehicle"] == vehicle and o["timestamp"].timestamp() > sess.get("last_delivered_ts", 0)
        ]

        if not new_otps:
            return jsonify({"status": "waiting"}), 200

        # newest OTP for this session
        latest = new_otps[-1]

        # store browser id in history — record per-browser delivery
        latest_with_browser = latest.copy()
        latest_with_browser["browser_id"] = browser_id
        otp_data[token].append(latest_with_browser)

        # update this session's last_delivered_ts so same session won't get same OTP again
        client_sessions[token][sess_key]["last_delivered_ts"] = latest["timestamp"].timestamp()

        return jsonify({
            "status": "success",
            "otp": latest["otp"],
            "vehicle": vehicle,
            "browser_id": browser_id,
            "timestamp": latest["timestamp"].strftime("%Y-%m-%d %H:%M:%S")
        }), 200

    # ========================
    # MOBILE OTP POLLING
    # ========================
    if sim_number not in mobile_groups[token]:
        return jsonify({"status": "waiting"}), 200

    all_otps = mobile_groups[token][sim_number]

    # Only deliver OTPs that are newer than this session's last_delivered_ts
    new_otps = [
        o for o in all_otps
        if o["timestamp"].timestamp() > sess.get("last_delivered_ts", 0)
    ]

    if not new_otps:
        return jsonify({"status": "waiting"}), 200

    # latest OTP for this session
    latest = new_otps[-1]

    # store browser id in otp_data history (per-browser)
    latest_with_browser = latest.copy()
    latest_with_browser["browser_id"] = browser_id
    otp_data[token].append(latest_with_browser)

    # update this session's last_delivered_ts so same session won't get same OTP again
    client_sessions[token][sess_key]["last_delivered_ts"] = latest["timestamp"].timestamp()

    return jsonify({
        "status": "success",
        "otp": latest["otp"],
        "sim_number": sim_number,
        "browser_id": browser_id,
        "timestamp": latest["timestamp"].strftime("%Y-%m-%d %H:%M:%S")
    }), 200


# =========================
# LOGIN DETECTION
# =========================
@app.route('/api/login-detect', methods=['POST'])
def login_detect():
    try:
        data = request.get_json(force=True)
        token = (data.get('token') or "").strip()
        mobile_number = (data.get('mobile_number') or "").strip().upper()
        source = (data.get('source') or "").strip().upper()

        if not mobile_number or not token:
            return jsonify({"status": "error", "message": "mobile_number and token required"}), 400
        if not valid_token(token):
            return jsonify({"status": "error", "message": "Invalid token"}), 403

        entry = {"timestamp": datetime.now(IST), "source": source}
        login_sessions[token].setdefault(mobile_number, []).append(entry)

        return jsonify({"status": "success"}), 200

    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 400


@app.route('/api/login-found', methods=['GET'])
def login_found():
    token = (request.args.get('token') or "").strip()
    mobile_number = (request.args.get('mobile_number') or "").strip().upper()

    if not token or not mobile_number:
        return jsonify({"status": "error", "message": "token + mobile_number required"}), 400
    if not valid_token(token):
        return jsonify({"status": "error", "message": "Invalid token"}), 403

    if mobile_number in login_sessions[token]:
        detections = [
            {
                "timestamp": e["timestamp"].strftime("%Y-%m-%d %H:%M:%S"),
                "source": e.get("source","")
            } for e in login_sessions[token][mobile_number]
        ]
        return jsonify({
            "status": "found",
            "mobile_number": mobile_number,
            "detections": detections
        }), 200

    return jsonify({"status": "not_found", "mobile_number": mobile_number}), 200


@app.route('/api/check-login-status', methods=['GET'])
def check_login_status():
    return """
    <html><body>
        <div style="position:absolute;top:10px;left:10px;font-size:16px;">
            already logged in
        </div>
    </body></html>
    """



# =========================
# Admin Login + Dashboard (start)
# =========================
admin_login_page = """
<html><head><title>Admin Login</title></head>
<body style="font-family:Segoe UI, Arial, sans-serif;display:flex;justify-content:center;align-items:center;height:100vh;background:#f4f6f9;">
<div style="background:white;padding:30px;border-radius:10px;box-shadow:0px 8px 30px rgba(0,0,0,0.06);width:380px;">
<h1 style="text-align:center;color:#2980B9;margin:0;font-size:28px;">ADMIN</h1>
<p style="text-align:center;color:#2980B9;margin:6px 0 18px;">Log In To Dashboard</p>
{% if error %}<p style="color:red;text-align:center">{{error}}</p>{% endif %}
<form method="POST">
<label style="font-size:13px;color:#333;">Username</label>
<input type="text" name="username" placeholder="Enter username" required style="width:100%;padding:10px;margin:6px 0 12px;border-radius:6px;border:1px solid #ddd;">
<label style="font-size:13px;color:#333;">Password</label>
<input type="password" name="password" placeholder="Enter password" required style="width:100%;padding:10px;margin:6px 0 12px;border-radius:6px;border:1px solid #ddd;">
<button style="width:100%;padding:12px;background:#2980B9;color:white;border:none;border-radius:6px;font-weight:600;">Login</button>
</form>
</div></body></html>
"""

@app.route('/admin-login', methods=['GET','POST'])
def admin_login():
    global ADMIN_PASSWORD
    if request.method == 'POST':
        user = (request.form.get("username") or "").strip().upper()
        pwd = (request.form.get("password") or "").strip()
        if user != "ADMIN":
            return render_template_string(admin_login_page, error="Wrong username")
        if pwd != ADMIN_PASSWORD:
            return render_template_string(admin_login_page, error="Wrong password")
        session["is_admin"] = True
        return redirect(url_for("admin"))
    return render_template_string(admin_login_page, error=None)

@app.route('/admin-logout')
def admin_logout():
    session.pop("is_admin", None)
    return redirect(url_for("admin_login"))

# Helper to render token partials (used by both admin embed and token dashboard)
def render_token_section_partial(token, section):
    # OTP section with delete forms (works when embedded)
    if section == "otp":
        rows = ""
        for i, e in enumerate(otp_data[token]):
            ts = e.get("timestamp", e.get("removed_at", datetime.now(IST))).strftime("%Y-%m-%d %H:%M:%S")
            rows += f"<tr><td><input type='checkbox' name='otp_rows' value='{i}'></td><td>{e.get('sim_number','')}</td><td>{e.get('vehicle','')}</td><td>{e.get('otp','')}</td><td>{e.get('browser_id','')}</td><td>{ts}</td><td>{e.get('removed_reason','')}</td></tr>"
        partial = f"""
        <div class="card">
            <h3>OTP Data - {token}</h3>
            <form method="POST" action="/status/{token}?embed=1&section=otp">
            <table style="width:100%;border-collapse:collapse;">
                <tr style="background:#2980B9;color:white;"><th>Select</th><th>Mobile</th><th>Vehicle</th><th>OTP</th><th>Browser</th><th>Date</th><th>Reason</th></tr>
                {rows if rows else '<tr><td colspan="7" style="padding:12px">No OTPs found</td></tr>'}
            </table>
            <div style="margin-top:10px;">
                <button type="submit" name="delete_selected_otps" style="padding:8px 10px;background:#e67e22;color:white;border:none;border-radius:6px;">Delete Selected</button>
                <button type="submit" name="delete_all_otps" style="padding:8px 10px;background:#c0392b;color:white;border:none;border-radius:6px;margin-left:8px;">Delete All</button>
            </div>
            </form>
        </div>
        """
        return partial

    # Login section with delete forms
    if section == "login":
        rows = ""
        for m, entries in login_sessions[token].items():
            for i, e in enumerate(entries):
                rows += f"<tr><td><input type='checkbox' name='login_rows' value='{m}:{i}'></td><td>{m}</td><td>{e['timestamp'].strftime('%Y-%m-%d %H:%M:%S')}</td><td>{e.get('source','')}</td></tr>"
        partial = f"""
        <div class="card">
            <h3>Login Detections - {token}</h3>
            <form method="POST" action="/status/{token}?embed=1&section=login">
            <table style="width:100%;border-collapse:collapse;">
                <tr style="background:#2980B9;color:white;"><th>Select</th><th>Mobile</th><th>Date</th><th>Source</th></tr>
                {rows if rows else '<tr><td colspan="4" style="padding:12px">No login detections</td></tr>'}
            </table>
            <div style="margin-top:10px;">
                <button type="submit" name="delete_selected_logins" style="padding:8px 10px;background:#e67e22;color:white;border:none;border-radius:6px;">Delete Selected</button>
                <button type="submit" name="delete_all_logins" style="padding:8px 10px;background:#c0392b;color:white;border:none;border-radius:6px;margin-left:8px;">Delete All</button>
            </div>
            </form>
        </div>
        """
        return partial

    # Change password partial (for embed and token)
    if section == "change_password":
        partial = f"""
        <div class="card">
            <h3>Change Token Password - {token}</h3>
            <form method="POST" action="/change-password/{token}">
                <label>Current Password</label><input type="password" name="current_password" required style="padding:8px;margin-top:6px;width:100%;border-radius:6px;border:1px solid #ddd;">
                <label style="margin-top:8px">New Password</label><input type="password" name="new_password" required style="padding:8px;margin-top:6px;width:100%;border-radius:6px;border:1px solid #ddd;">
                <label style="margin-top:8px">Confirm Password</label><input type="password" name="confirm_password" required style="padding:8px;margin-top:6px;width:100%;border-radius:6px;border:1px solid #ddd;">
                <div style="margin-top:10px;"><button type="submit" style="background:#27AE60;color:white;padding:8px 12px;border:none;border-radius:6px;">Change</button></div>
            </form>
        </div>
        """
        return partial

    return "<div class='card'><p>Invalid section</p></div>"

# Admin endpoint to change token password
@app.route('/admin/change-token-password/<token>', methods=['POST'])
def admin_change_token_password(token):
    if not session.get("is_admin"):
        return redirect(url_for("admin_login"))
    if token not in PREDEFINED_TOKENS:
        return "Invalid token", 404
    new = request.form.get("new_password")
    conf = request.form.get("confirm_password")
    if not new or new != conf:
        return "Passwords do not match", 400
    token_passwords[token] = new
    return f"Password for {token} updated."

# Admin endpoint to show login details (token username + password) - embed partial
@app.route('/admin/token-login-details/<token>', methods=['GET'])
def admin_token_login_details(token):
    if not session.get("is_admin"):
        return redirect(url_for("admin_login"))
    if token not in PREDEFINED_TOKENS:
        return "Invalid token", 404
    if request.args.get("embed") == "1":
        pwd = token_passwords.get(token, "")
        partial = f"""
        <div class="card">
            <h3>Login Details - {token}</h3>
            <p><strong>Username:</strong> {token}</p>
            <p><strong>Password:</strong> {pwd}</p>
            <p class="muted">Admin can change password using the Change Password panel.</p>
        </div>
        """
        return partial
    return redirect(url_for("admin"))

# Admin: master reset panel (OPTION 1 applied - removed undefined mobile_otps and browser_queues)
@app.route('/admin/master-reset', methods=['GET', 'POST'])
def admin_master_reset():
    if not session.get("is_admin"):
        return redirect(url_for("admin_login"))

    if request.method == 'POST':
        reset_otp_data = 'otp_data' in request.form
        reset_login_sessions = 'login_sessions' in request.form
        reset_processed_mobiles = 'processed_mobiles' in request.form
        reset_mobile_otps = 'mobile_otps' in request.form
        reset_vehicle_otps = 'vehicle_otps' in request.form
        reset_browser_queues = 'browser_queues' in request.form
        reset_all = 'reset_all' in request.form

        if reset_all:
            for token in PREDEFINED_TOKENS:
                otp_data[token].clear()
                login_sessions[token].clear()
                token_processed_mobiles[token].clear()
                # mobile_otps and browser_queues removed (Option 1)
                vehicle_otps[token].clear()
                client_sessions[token].clear()
        else:
            for token in PREDEFINED_TOKENS:
                if reset_otp_data:
                    otp_data[token].clear()
                if reset_login_sessions:
                    login_sessions[token].clear()
                if reset_processed_mobiles:
                    token_processed_mobiles[token].clear()
                if reset_mobile_otps:
                    # nothing named mobile_otps exists — skip (Option 1)
                    pass
                if reset_vehicle_otps:
                    vehicle_otps[token].clear()
                if reset_browser_queues:
                    # browser_queues not defined — instead clear client_sessions as the closest equivalent
                    client_sessions[token].clear()
        return redirect(url_for("admin"))

    if request.args.get("embed") == "1":
        partial = """
        <div class="card">
            <h3>Master Reset</h3>
            <p class="muted">Select data to reset across all tokens. This action cannot be undone.</p>
            <form method="POST" action="/admin/master-reset" onsubmit="return confirm('Are you sure you want to reset the selected data? This cannot be undone.');">
                <label><input type="checkbox" name="otp_data"> OTP Data (all delivered/removed OTPs)</label><br>
                <label><input type="checkbox" name="login_sessions"> Login Detections</label><br>
                <label><input type="checkbox" name="processed_mobiles"> Processed Mobiles</label><br>
                <label><input type="checkbox" name="mobile_otps"> Mobile OTPs (pending)</label><br>
                <label><input type="checkbox" name="vehicle_otps"> Vehicle OTPs (pending)</label><br>
                <label><input type="checkbox" name="browser_queues"> Browser Queues & Client Sessions</label><br>
                <label><input type="checkbox" name="reset_all"> Reset All Data</label><br>
                <div style="margin-top:10px;">
                    <button type="submit" style="padding:8px 10px;background:#c0392b;color:white;border:none;border-radius:6px;">Reset Selected</button>
                </div>
            </form>
        </div>
        """
        return partial
    return redirect(url_for("admin"))

# =========================
# Admin main UI
# =========================
@app.route('/admin', methods=['GET'])
def admin():
    if not session.get("is_admin"):
        return redirect(url_for("admin_login"))

    tokens_js_list = "[" + ",".join([f"'{t}'" for t in PREDEFINED_TOKENS]) + "]"

    html = f"""
    <html>
    <head>
        <title>Admin Dashboard</title>
        <style>
            body {{ font-family: 'Segoe UI', Arial, sans-serif; margin:0; background:#f4f6f9; }}
            .app {{ display:flex; min-height:100vh; }}
            .sidebar {{ width:260px; background:#2C3E50; color:white; padding:22px; box-sizing:border-box; display:flex; flex-direction:column; }}
            .sidebar h2 {{ margin:0 0 14px; font-size:20px; text-align:center; color:#fff; }}
            .sidebar a.menu-link {{ display:block; padding:10px; margin-bottom:8px; color:#fff; text-decoration:none; background:rgba(255,255,255,0.03); border-radius:6px; }}
            .main {{ flex-grow:1; padding:24px; }}
            .card {{ background:white; padding:16px; border-radius:8px; box-shadow:0px 4px 18px rgba(0,0,0,0.06); margin-bottom:20px; }}
            table {{ width:100%; border-collapse:collapse; }}
            table th {{ background:#2980B9; color:white; padding:10px; text-align:left; }}
            table td {{ padding:10px; border-bottom:1px solid #eee; }}
            .tokens-grid {{ display:flex; gap:12px; flex-wrap:wrap; }}
            .token-tile {{ padding:12px;background:#ecf0f1;border-radius:6px;width:160px;text-align:center;cursor:pointer;font-weight:700;color:#2C3E50; }}
            .muted {{ color:#666; font-size:13px; }}
            .inline-btn {{ padding:6px 8px;background:#2980B9;color:#fff;border-radius:6px;border:none;cursor:pointer;margin-left:6px; }}
        </style>
        <script>
            function loadTokens() {{
                var tokens = {tokens_js_list};
                var html = "<div class='card'><h3>Tokens</h3><div class='tokens-grid'>";
                tokens.forEach(function(t) {{
                    html += "<div class='token-tile' onclick=\\"loadTokenFull('" + t + "')\\">" + t + "</div>";
                }});
                html += "</div></div>";
                document.getElementById('content_panel').innerHTML = html;
            }}
            function loadTokenFull(token) {{
                document.getElementById('content_panel').innerHTML = "<div class='card'><p>Loading token dashboard...</p></div>";
                fetch('/status/' + token + '?embed=admin_full', {{ credentials: 'same-origin' }})
                    .then(function(r){{ return r.text(); }})
                    .then(function(html){{ document.getElementById('content_panel').innerHTML = html; }})
                    .catch(function(e){{ document.getElementById('content_panel').innerHTML = "<div class='card' style='color:red'>Failed to load</div>"; }});
            }}
            function loadLimit() {{
                var tokens = {tokens_js_list};
                var html = "<div class='card'><h3>Limit Exceeded - Select Token</h3><div class='tokens-grid'>";
                tokens.forEach(function(t) {{
                    html += "<div class='token-tile' onclick=\\"loadLimitToken('" + t + "')\\">" + t + "</div>";
                }});
                html += "</div></div>";
                document.getElementById('content_panel').innerHTML = html;
            }}
            function loadLimitToken(token) {{
                document.getElementById('content_panel').innerHTML = "<div class='card'><p>Loading limit-exceeded...</p></div>";
                fetch('/admin/limit/' + token + '?embed=1', {{ credentials: 'same-origin' }})
                    .then(function(r){{ return r.text(); }})
                    .then(function(html){{ document.getElementById('content_panel').innerHTML = html; }})
                    .catch(function(e){{ document.getElementById('content_panel').innerHTML = "<div class='card' style='color:red'>Failed to load</div>"; }});
            }}
            function loadCaps() {{
                document.getElementById('content_panel').innerHTML = "<div class='card'><p>Loading caps...</p></div>";
                fetch('/admin/caps?embed=1', {{ credentials: 'same-origin' }})
                    .then(function(r){{ return r.text(); }})
                    .then(function(html){{ document.getElementById('content_panel').innerHTML = html; }})
                    .catch(function(e){{ document.getElementById('content_panel').innerHTML = "<div class='card' style='color:red'>Failed to load</div>"; }});
            }}
            function loadAdminChangePassword() {{
                document.getElementById('content_panel').innerHTML = "<div class='card'><p>Loading...</p></div>";
                fetch('/admin/change-password?embed=1', {{ credentials: 'same-origin' }})
                    .then(function(r){{ return r.text(); }})
                    .then(function(html){{ document.getElementById('content_panel').innerHTML = html; }})
                    .catch(function(e){{ document.getElementById('content_panel').innerHTML = "<div class='card' style='color:red'>Failed to load</div>"; }});
            }}
            function loadMasterReset() {{
                document.getElementById('content_panel').innerHTML = "<div class='card'><p>Loading...</p></div>";
                fetch('/admin/master-reset?embed=1', {{ credentials: 'same-origin' }})
                    .then(function(r){{ return r.text(); }})
                    .then(function(html){{ document.getElementById('content_panel').innerHTML = html; }})
                    .catch(function(e){{ document.getElementById('content_panel').innerHTML = "<div class='card' style='color:red'>Failed to load</div>"; }});
            }}
            // server time updater (client-side)
            function updateServerTime() {{
                var now = new Date();
                document.getElementById('server_time').innerText = now.toLocaleString();
            }}
            setInterval(updateServerTime, 1000);
            window.onload = function() {{
                document.getElementById('content_panel').innerHTML = "<div class='card'><h3>Welcome, Admin</h3><p class='muted'>Click TOKENS or other actions on the left to fetch fresh data into this panel.</p></div>";
                updateServerTime();
            }};
            // inject processed mobiles below the caps table
            function showProcessedMobiles(token) {{
                var target = document.getElementById('processed_mobiles_container');
                if (!target) return;
                target.innerHTML = '<div class="card"><p>Loading...</p></div>';
                fetch('/admin/processed/' + token + '?embed=1', {{ credentials: 'same-origin' }})
                    .then(function(r) {{ return r.text(); }})
                    .then(function(html) {{ target.innerHTML = html; }})
                    .catch(function(e) {{ target.innerHTML = '<div class="card" style="color:red">Failed to load</div>'; }});
            }}
        </script>
    </head>
    <body>
        <div class="app">
            <div class="sidebar">
                <h2>ADMIN</h2>
                <a href="#" class="menu-link" onclick="loadTokens()">TOKENS</a>
                <a href="#" class="menu-link" onclick="loadLimit()">LIMIT EXCEEDED</a>
                <a href="#" class="menu-link" onclick="loadCaps()">TOKEN CAPS</a>
                <a href="#" class="menu-link" onclick="loadAdminChangePassword()">CHANGE ADMIN PASSWORD</a>
                <a href="#" class="menu-link" onclick="loadMasterReset()">MASTER RESET</a>
                <a href="/admin-logout" class="menu-link" style="background:#E74C3C;">LOGOUT</a>
                <div style="margin-top:auto;color:#bdc3c7;font-size:12px;padding-top:12px;">Server time: <span id="server_time"></span></div>
            </div>
            <div class="main">
                <div id="content_panel" class="card">
                    <h3>Welcome, Admin</h3>
                    <p class="muted">Use the left menu to view tokens, caps, limit-exceeded items, or reset data. All panels fetch fresh data when clicked.</p>
                </div>
            </div>
        </div>
    </body>
    </html>
    """
    return html

# Admin: limit view and delete (embed=1 partial)
@app.route('/admin/limit/<token>', methods=['GET','POST'])
def admin_limit(token):
    if not session.get("is_admin"):
        return redirect(url_for("admin_login"))
    if token not in PREDEFINED_TOKENS:
        return "Invalid token", 404

    if request.method == 'POST':
        if "delete_selected" in request.form:
            to_delete = [int(x) for x in request.form.getlist("otp_rows")]
            otp_data[token] = [e for i, e in enumerate(otp_data[token]) if not (i in to_delete and e.get("removed_reason") == "limit_exceeded")]
        elif "delete_all" in request.form:
            otp_data[token] = [e for e in otp_data[token] if e.get("removed_reason") != "limit_exceeded"]
        if request.args.get("embed") == "1":
            pass
        else:
            return redirect(url_for("admin_limit", token=token))

    rows = ""
    for i, e in enumerate(otp_data[token]):
        if e.get("removed_reason") == "limit_exceeded":
            ts = e.get("timestamp", e.get("removed_at", datetime.now(IST))).strftime("%Y-%m-%d %H:%M:%S")
            rows += f"<tr><td><input type='checkbox' name='otp_rows' value='{i}'></td><td>{e.get('sim_number','')}</td><td>{e.get('vehicle','')}</td><td>{e.get('otp','')}</td><td>{e.get('browser_id','')}</td><td>{ts}</td></tr>"

    if request.args.get("embed") == "1":
        partial = f"""
        <div class="card">
            <h3>Limit Exceeded - {token}</h3>
            <form method="POST" action="/admin/limit/{token}?embed=1">
                <table style="width:100%;border-collapse:collapse;">
                    <tr style="background:#E74C3C;color:white;"><th>Select</th><th>Mobile</th><th>Vehicle</th><th>OTP</th><th>Browser</th><th>Date</th></tr>
                    {rows if rows else '<tr><td colspan="6" style="padding:12px">No limit-exceeded OTPs</td></tr>'}
                </table>
                <div style="margin-top:10px;">
                    <button type="submit" name="delete_selected" style="padding:8px 10px;background:#e67e22;color:white;border:none;border-radius:6px;">Delete Selected</button>
                    <button type="submit" name="delete_all" style="padding:8px 10px;background:#c0392b;color:white;border:none;border-radius:6px;margin-left:8px;">Delete All</button>
                </div>
            </form>
        </div>
        """
        return partial

    return f"<html><body><pre>Limit Exceeded for {token}</pre></body></html>"

# Admin: caps view (embed + processed mobile inject)
@app.route('/admin/caps', methods=['GET'])
def admin_caps():
    if not session.get("is_admin"):
        return redirect(url_for("admin_login"))
    if request.args.get("embed") == "1":
        rows = ""
        idx = 0
        for t in PREDEFINED_TOKENS:
            rows += f"<tr id='cap_row_{idx}'><td>{t}</td><td style='text-align:center'>{len(token_processed_mobiles[t])}</td><td style='text-align:center'>{token_mobile_caps[t] if token_mobile_caps[t] is not None else 'Unlimited'}</td>"
            rows += f"<td><form method='POST' action='/admin/update-cap' style='display:inline-block'><input type='hidden' name='token' value='{t}'><input type='number' name='cap' placeholder='Enter cap' style='padding:6px;width:120px;margin-right:6px;'><button type='submit' class='primary' style='padding:6px 10px;background:#2980B9;color:white;border:none;border-radius:4px;'>Set</button></form>"
            rows += f"<button onclick=\"showProcessedMobiles('{t}')\" style='padding:6px 8px;background:#2ecc71;color:#fff;border-radius:6px;border:none;cursor:pointer;margin-left:8px;'>Processed Mobiles</button></td></tr>"
            idx += 1

        partial = f"""
        <div class="card">
            <h3>Token Mobile Caps</h3>
            <table style="width:100%;border-collapse:collapse;">
                <tr style="background:#2980B9;color:white;"><th>Token</th><th>Processed Mobiles</th><th>Cap</th><th>Action</th></tr>
                {rows}
            </table>
            <div id='processed_mobiles_container' style='margin-top:20px;'></div>
            <p class='muted' style="margin-top:10px;">Click <strong>Processed Mobiles</strong> to load processed mobile data below the table.</p>
        </div>
        """
        return partial
    return redirect(url_for("admin"))

@app.route('/admin/update-cap', methods=['POST'])
def admin_update_cap():
    if not session.get("is_admin"):
        return redirect(url_for("admin_login"))
    t = request.form.get("token")
    cap = request.form.get("cap")
    if t in PREDEFINED_TOKENS:
        token_mobile_caps[t] = int(cap) if cap else None
        return redirect(url_for("admin_caps", embed=1))
    return "Invalid token", 400

@app.route('/admin/processed/<token>', methods=['GET'])
def admin_processed(token):
    if not session.get("is_admin"):
        return redirect(url_for("admin_login"))
    if token not in PREDEFINED_TOKENS:
        return "Invalid token", 404
    if request.args.get("embed") == "1":
        rows = ""
        for m in sorted(token_processed_mobiles[token]):
            related = [e for e in otp_data[token] if e.get("sim_number")==m]
            if related:
                for e in related:
                    ts = e.get("timestamp", e.get("removed_at", datetime.now(IST))).strftime("%Y-%m-%d %H:%M:%S")
                    rows += f"<tr><td>{m}</td><td>{e.get('otp','')}</td><td>{e.get('removed_reason','')}</td><td>{ts}</td></tr>"
            else:
                rows += f"<tr><td>{m}</td><td></td><td></td><td></td></tr>"
        partial = f"""
        <div style="padding:12px 0;">
            <h4>Processed mobiles - {token}</h4>
            <table style="width:100%;border-collapse:collapse;">
                <tr style="background:#2980B9;color:white;"><th>Mobile</th><th>OTP</th><th>Reason</th><th>Date</th></tr>
                {rows if rows else '<tr><td colspan="4" style="padding:12px">No processed mobiles</td></tr>'}
            </table>
        </div>
        """
        return partial
    return "Not allowed", 403

# Admin change password panel (embed)
@app.route('/admin/change-password', methods=['GET','POST'])
def admin_change_password():
    global ADMIN_PASSWORD
    if not session.get("is_admin"):
        return redirect(url_for("admin_login"))
    if request.method == "POST":
        cur = request.form.get("current_password")
        new = request.form.get("new_password")
        conf = request.form.get("confirm_password")
        if cur != ADMIN_PASSWORD:
            return "Current password incorrect", 400
        if new != conf:
            return "Passwords do not match", 400
        ADMIN_PASSWORD = new
        return "Admin password changed."
    if request.args.get("embed") == "1":
        return """
        <div class="card">
            <h3>Change Admin Password</h3>
            <form method="POST" action="/admin/change-password">
                <label>Current Password</label><input type="password" name="current_password" required style="padding:8px;width:100%;border-radius:6px;border:1px solid #ddd;"><br>
                <label>New Password</label><input type="password" name="new_password" required style="padding:8px;width:100%;border-radius:6px;border:1px solid #ddd;"><br>
                <label>Confirm Password</label><input type="password" name="confirm_password" required style="padding:8px;width:100%;border-radius:6px;border:1px solid #ddd;"><br>
                <div style="margin-top:8px;"><button type="submit" class="primary" style="padding:8px 10px;background:#2980B9;color:white;border:none;border-radius:6px;">Change Password</button></div>
            </form>
        </div>
        """
    return redirect(url_for("admin"))

# =========================
# Token login/dashboard
# =========================
login_page_html = """
<html><head><title>Login</title></head>
<body style="font-family:Segoe UI;display:flex;justify-content:center;align-items:center;height:100vh;background:#f4f6f9;">
<div style="background:white;padding:30px;border-radius:10px;box-shadow:0px 8px 30px rgba(0,0,0,0.06);width:380px;">
<h1 style="text-align:center;color:#2980B9;margin:0;font-size:28px;">KM OTP</h1>
<p style="text-align:center;color:#2980B9;margin:6px 0 18px;">Log In To Your Account</p>
{% if error %}<p style="color:red;text-align:center">{{error}}</p>{% endif %}
<form method="POST">
<label style="font-weight:700;color:#333;">Token</label>
<input type="text" name="token" placeholder="Enter your token" required style="width:100%;padding:10px;margin:6px 0 12px;border-radius:6px;border:1px solid #ddd;">
<label style="font-weight:700;color:#333;">Password</label>
<input type="password" name="password" placeholder="Enter password" required style="width:100%;padding:10px;margin:6px 0 12px;border-radius:6px;border:1px solid #ddd;">
<button style="width:100%;padding:12px;background:#2980B9;color:white;border:none;border-radius:6px;font-weight:700;">Login</button>
</form>
</div></body></html>
"""

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        token = (request.form.get("token") or "").strip()
        pwd = (request.form.get("password") or "").strip()
        if token not in PREDEFINED_TOKENS:
            return render_template_string(login_page_html, error="Wrong token")
        if pwd != token_passwords[token]:
            return render_template_string(login_page_html, error="Wrong password")
        session["token"] = token
        return redirect(url_for("status", token=token))
    return render_template_string(login_page_html, error=None)

@app.route('/logout')
def logout():
    session.pop("token", None)
    return redirect(url_for("login"))

@app.route('/change-password/<token>', methods=['POST'])
def change_password(token):
    # Only token owner may change their password via token dashboard (not admin)
    if "token" not in session or session["token"] != token:
        return redirect(url_for("login"))
    cur = request.form.get("current_password")
    new = request.form.get("new_password")
    confirm = request.form.get("confirm_password")
    if cur != token_passwords[token]:
        return redirect(url_for("status", token=token, err="wrong_current"))
    if new != confirm:
        return redirect(url_for("status", token=token, err="nomatch"))
    token_passwords[token] = new
    return redirect(url_for("status", token=token, msg="changed"))

# =========================
# Token dashboard / partials / admin_full (for admin full token dashboard)
# =========================
@app.route('/status/<token>', methods=['GET','POST'])
def status(token):
    # allow admin direct access OR token-login access
    if not (("token" in session and session["token"] == token) or session.get("is_admin")):
        return redirect(url_for("login"))

    # handle deletes when embed=1 (partials) or full page form posts
    if request.method == 'POST':
        # OTP deletes
        if "delete_selected_otps" in request.form:
            to_delete = [int(x) for x in request.form.getlist("otp_rows")]
            otp_data[token] = [e for i, e in enumerate(otp_data[token]) if i not in to_delete]
            if request.args.get('embed') == '1':
                return render_token_section_partial(token, 'otp')
        elif "delete_all_otps" in request.form:
            otp_data[token].clear()
            if request.args.get('embed') == '1':
                return render_token_section_partial(token, 'otp')
        # Login deletes
        elif "delete_selected_logins" in request.form:
            to_delete = request.form.getlist("login_rows")
            for x in to_delete:
                m, idx = x.split(":")
                idx = int(idx)
                if m in login_sessions[token] and 0 <= idx < len(login_sessions[token][m]):
                    login_sessions[token][m].pop(idx)
                    if not login_sessions[token][m]:
                        login_sessions[token].pop(m)
            if request.args.get('embed') == '1':
                return render_token_section_partial(token, 'login')
        elif "delete_all_logins" in request.form:
            login_sessions[token].clear()
            if request.args.get('embed') == '1':
                return render_token_section_partial(token, 'login')

        # For non-embed POST requests (full page), re-render the dashboard
        if request.args.get('embed') != '1':
            if request.args.get('embed') == 'admin_full':
                # Admin full dashboard
                token_full_html = f"""
                <div style="display:flex;gap:18px;align-items:flex-start;">
                    <div style="width:220px;background:#2C3E50;color:#fff;padding:12px;border-radius:8px;">
                        <h3 style="margin:6px 0 12px;text-align:center;">{token}</h3>
                        <button style="width:100%;padding:10px;margin-bottom:8px;border:none;border-radius:6px;background:#3498DB;color:white;cursor:pointer;" onclick="document.getElementById('token_right_panel').innerHTML='<div class=\\'card\\'><p>Loading...</p></div>';fetch('/status/{token}?embed=1&section=otp').then(r=>r.text()).then(h=>document.getElementById('token_right_panel').innerHTML=h);">OTP DATA</button>
                        <button style="width:100%;padding:10px;margin-bottom:8px;border:none;border-radius:6px;background:#3498DB;color:white;cursor:pointer;" onclick="document.getElementById('token_right_panel').innerHTML='<div class=\\'card\\'><p>Loading...</p></div>';fetch('/status/{token}?embed=1&section=login').then(r=>r.text()).then(h=>document.getElementById('token_right_panel').innerHTML=h);">LOGIN DETECTIONS</button>
                        <button style="width:100%;padding:10px;margin-bottom:8px;border:none;border-radius:6px;background:#27AE60;color:white;cursor:pointer;" onclick="document.getElementById('token_right_panel').innerHTML='<div class=\\'card\\'><p>Loading...</p></div>';fetch('/status/{token}?embed=1&section=change_password').then(r=>r.text()).then(h=>document.getElementById('token_right_panel').innerHTML=h);">CHANGE PASSWORD</button>
                        <!-- admin-only: show login details -->
                        <button style="width:100%;padding:10px;margin-bottom:8px;border:none;border-radius:6px;background:#9b59b6;color:white;cursor:pointer;" onclick="document.getElementById('token_right_panel').innerHTML='<div class=\\'card\\'><p>Loading login details...</p></div>';fetch('/admin/token-login-details/{token}?embed=1').then(r=>r.text()).then(h=>document.getElementById('token_right_panel').innerHTML=h);">LOGIN DETAILS</button>
                    </div>
                    <div style="flex:1;" id="token_right_panel">
                        <!-- initial load OTP partial -->
                        {render_token_section_partial(token,'otp')}
                    </div>
                </div>
                """
                return token_full_html
            else:
                # Token user dashboard
                html = f"""
                <html>
                <head>
                    <title>{token} Dashboard</title>
                    <style>
                        body {{ font-family: 'Segoe UI', sans-serif; background:#f9f9f9; margin:0; }}
                        h2 {{ margin:20px 0; text-align:center; color:#2C3E50; }}
                        .container {{ display:flex; min-height:100vh; }}
                        .sidebar {{ width:220px; background:#2C3E50; padding:20px; color:white; }}
                        .sidebar button {{ margin-bottom:15px; width:100%; padding:10px; border:none; background:#3498DB; color:white; cursor:pointer; border-radius:6px; font-weight:700; }}
                        .content {{ flex-grow:1; padding:30px; }}
                        .card {{ background:white; padding:16px; border-radius:8px; box-shadow:0px 4px 14px rgba(0,0,0,0.06); }}
                        table {{ border-collapse: collapse; width:100%; background:white; }}
                        th, td {{ border:1px solid #ddd; padding:8px; }}
                        th {{ background:#2980B9; color:white; }}
                    </style>
                    <script>
                        function loadSection(section) {{
                            var url = window.location.pathname + '?embed=1&section=' + section;
                            document.getElementById('right_panel').innerHTML = '<div class="card"><p>Loading...</p></div>';
                            fetch(url, {{ credentials: 'same-origin' }})
                                .then(function(r){{ return r.text(); }})
                                .then(function(html){{ document.getElementById('right_panel').innerHTML = html; }})
                                .catch(function(e){{ document.getElementById('right_panel').innerHTML = '<div class="card" style="color:red">Failed to load</div>'; }});
                        }}
                        window.onload = function() {{ loadSection('otp'); }}
                    </script>
                </head>
                <body>
                    <h2>KM OTP Dashboard ({token})</h2>
                    <div class="container">
                        <div class="sidebar">
                            <button onclick="loadSection('otp')">OTP DATA</button>
                            <button onclick="loadSection('login')">LOGIN DETECTIONS</button>
                            <button onclick="loadSection('change_password')">CHANGE PASSWORD</button>
                            <a href="/logout" style="color:white;text-decoration:none;"><button>LOGOUT</button></a>
                        </div>
                        <div class="content">
                            <div id="right_panel" class="card">
                                <!-- dynamic content will load here -->
                            </div>
                        </div>
                    </div>
                </body>
                </html>
                """
                return html

    # If embed=1 return partial for requested section
    if request.args.get('embed') == '1':
        section = request.args.get('section', 'otp')
        return render_token_section_partial(token, section)

    # If embed=admin_full -> return full token dashboard (with token sidebar) for admin
    if request.args.get('embed') == 'admin_full':
        token_full_html = f"""
        <div style="display:flex;gap:18px;align-items:flex-start;">
            <div style="width:220px;background:#2C3E50;color:#fff;padding:12px;border-radius:8px;">
                <h3 style="margin:6px 0 12px;text-align:center;">{token}</h3>
                <button style="width:100%;padding:10px;margin-bottom:8px;border:none;border-radius:6px;background:#3498DB;color:white;cursor:pointer;" onclick="document.getElementById('token_right_panel').innerHTML='<div class=\\'card\\'><p>Loading...</p></div>';fetch('/status/{token}?embed=1&section=otp').then(r=>r.text()).then(h=>document.getElementById('token_right_panel').innerHTML=h);">OTP DATA</button>
                <button style="width:100%;padding:10px;margin-bottom:8px;border:none;border-radius:6px;background:#3498DB;color:white;cursor:pointer;" onclick="document.getElementById('token_right_panel').innerHTML='<div class=\\'card\\'><p>Loading...</p></div>';fetch('/status/{token}?embed=1&section=login').then(r=>r.text()).then(h=>document.getElementById('token_right_panel').innerHTML=h);">LOGIN DETECTIONS</button>
                <button style="width:100%;padding:10px;margin-bottom:8px;border:none;border-radius:6px;background:#27AE60;color:white;cursor:pointer;" onclick="document.getElementById('token_right_panel').innerHTML='<div class=\\'card\\'><p>Loading...</p></div>';fetch('/status/{token}?embed=1&section=change_password').then(r=>r.text()).then(h=>document.getElementById('token_right_panel').innerHTML=h);">CHANGE PASSWORD</button>
                <button style="width:100%;padding:10px;margin-bottom:8px;border:none;border-radius:6px;background:#9b59b6;color:white;cursor:pointer;" onclick="document.getElementById('token_right_panel').innerHTML='<div class=\\'card\\'><p>Loading login details...</p></div>';fetch('/admin/token-login-details/{token}?embed=1').then(r=>r.text()).then(h=>document.getElementById('token_right_panel').innerHTML=h);">LOGIN DETAILS</button>
            </div>
            <div style="flex:1;" id="token_right_panel">
                {render_token_section_partial(token,'otp')}
            </div>
        </div>
        """
        return token_full_html

    # Full token dashboard page (for token user)
    html = f"""
    <html>
    <head>
        <title>{token} Dashboard</title>
        <style>
            body {{ font-family: 'Segoe UI', sans-serif; background:#f9f9f9; margin:0; }}
            h2 {{ margin:20px 0; text-align:center; color:#2C3E50; }}
            .container {{ display:flex; min-height:100vh; }}
            .sidebar {{ width:220px; background:#2C3E50; padding:20px; color:white; }}
            .sidebar button {{ margin-bottom:15px; width:100%; padding:10px; border:none; background:#3498DB; color:white; cursor:pointer; border-radius:6px; font-weight:700; }}
            .content {{ flex-grow:1; padding:30px; }}
            .card {{ background:white; padding:16px; border-radius:8px; box-shadow:0px 4px 14px rgba(0,0,0,0.06); }}
            table {{ border-collapse: collapse; width:100%; background:white; }}
            th, td {{ border:1px solid #ddd; padding:8px; }}
            th {{ background:#2980B9; color:white; }}
        </style>
        <script>
            function loadSection(section) {{
                var url = window.location.pathname + '?embed=1&section=' + section;
                document.getElementById('right_panel').innerHTML = '<div class="card"><p>Loading...</p></div>';
                fetch(url, {{ credentials: 'same-origin' }})
                    .then(function(r){{ return r.text(); }})
                    .then(function(html){{ document.getElementById('right_panel').innerHTML = html; }})
                    .catch(function(e){{ document.getElementById('right_panel').innerHTML = '<div class="card" style="color:red">Failed to load</div>'; }});
            }}
            window.onload = function() {{ loadSection('otp'); }}
        </script>
    </head>
    <body>
        <h2>KM OTP Dashboard ({token})</h2>
        <div class="container">
            <div class="sidebar">
                <button onclick="loadSection('otp')">OTP DATA</button>
                <button onclick="loadSection('login')">LOGIN DETECTIONS</button>
                <button onclick="loadSection('change_password')">CHANGE PASSWORD</button>
                <a href="/logout" style="color:white;text-decoration:none;"><button>LOGOUT</button></a>
            </div>
            <div class="content">
                <div id="right_panel" class="card">
                    <!-- dynamic content will load here -->
                </div>
            </div>
        </div>
    </body>
    </html>
    """
    return html


# =========================
# Run Server
# =========================
if __name__ == '__main__':
    app.run(debug=True)
