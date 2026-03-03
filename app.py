from flask import Flask, render_template, request, redirect, url_for, send_file

# core modules
from modules.scanner import scan_network
from modules.port_scanner import scan_ports
from modules.vulnerability_engine import detect_vulnerabilities
from modules.risk_engine import calculate_risk
from modules.recommendation_engine import recommend
from modules.auth import require_login, login_user, logout_user, current_user, verify_password, hash_password
from database import models

app = Flask(__name__)
import config
app.secret_key = config.SECRET_KEY

@app.route("/")
def home():
    return render_template("index.html")


@app.route("/debug-method", methods=["GET", "POST"])
def debug_method():
    # Helpful quick endpoint to see which HTTP method the client used.
    return f"debug-method: {request.method}", 200

@app.route("/scan", methods=["GET", "POST"])
def scan():
    if request.method == "POST":
        ip_range = request.form.get("ip_range")
        # perform both host discovery and port/service scan for richer data
        try:
            hosts = scan_network(ip_range)
            ports = scan_ports(ip_range)
            vulns = detect_vulnerabilities(ports)
            risk = calculate_risk(vulns)
            recs = recommend(vulns)

            # persist scan to database
            import datetime
            conn = models.get_connection()
            cur = conn.cursor()
            cur.execute(
                "INSERT INTO scans (target_ip, scan_date, risk_score, risk_level) VALUES (?,?,?,?)",
                (ip_range, datetime.datetime.utcnow().isoformat(), risk['score'], risk['level'])
            )
            scan_id = cur.lastrowid
            for v in vulns:
                cur.execute(
                    "INSERT INTO vulnerabilities (scan_id, issue, severity, description) VALUES (?,?,?,?)",
                    (scan_id, v['issue'], v['severity'], v['description'])
                )
            conn.commit()
            conn.close()

            return render_template("results.html", results=hosts, ports=ports, vulnerabilities=vulns, risk=risk, recommendations=recs)
        except Exception as e:
            import traceback
            error = str(e)
            tb = traceback.format_exc()
            print(f"SCAN ERROR: {error}\n{tb}", file=__import__('sys').stderr)
            return render_template("results.html", results=[], ports=[], vulnerabilities=[], risk={}, recommendations=[], error=error)

    return render_template("index.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        conn = models.get_connection()
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cur.fetchone()
        conn.close()
        if user and verify_password(user["password_hash"], password):
            login_user(user["id"])
            return redirect(url_for("dashboard"))
        else:
            return render_template("login.html", error="Invalid credentials")
    return render_template("login.html")


@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for("home"))


@app.route("/dashboard")
@require_login
def dashboard():
    user = current_user()
    # simple stats by querying database
    conn = models.get_connection()
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM scans")
    total_scans = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM vulnerabilities")
    vuln_count = cur.fetchone()[0]
    cur.execute("SELECT risk_level, COUNT(*) FROM scans GROUP BY risk_level")
    levels = {row[0]: row[1] for row in cur.fetchall()}
    conn.close()
    stats = {
        "total_scans": total_scans,
        "devices_up": 0,
        "vuln_count": vuln_count,
        "risk_level": max(levels, key=lambda l: levels[l]) if levels else "Low",
        "high": levels.get("High", 0),
        "medium": levels.get("Medium", 0),
        "low": levels.get("Low", 0),
    }
    return render_template("dashboard.html", user=user, stats=stats)


@app.route("/report")
@require_login
def report():
    # for now render a simple report page
    return render_template("report.html")


if __name__ == "__main__":
    models.initialize()
    app.run(debug=True)