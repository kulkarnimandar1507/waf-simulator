"""
WAF Simulator — Main Flask Application
"""

import sqlite3
import os
from datetime import datetime
from functools import wraps
from flask import (
    Flask, render_template, request, redirect, url_for,
    session, flash
)
from werkzeug.security import generate_password_hash, check_password_hash

from waf.rules import inspect
from waf.middleware import (
    waf_check, FAILED_LOGINS, BRUTE_FORCE_THRESHOLD,
    log_request, reset_brute_force
)

# -------------------------------------------------------------------
# Absolute paths (works locally, on Render, on PythonAnywhere)
# -------------------------------------------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
INSTANCE_DIR = os.path.join(BASE_DIR, 'instance')
DB_PATH = os.path.join(INSTANCE_DIR, 'waf.db')

# Ensure instance folder exists before anything else
os.makedirs(INSTANCE_DIR, exist_ok=True)

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'dev-key-change-in-production')

WAF_STATE = {'enabled': True}


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    os.makedirs(INSTANCE_DIR, exist_ok=True)
    conn = get_db()
    c = conn.cursor()

    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        created_at TEXT
    )''')

    c.execute('''CREATE TABLE IF NOT EXISTS attack_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip TEXT, attack_type TEXT, payload TEXT, path TEXT, timestamp TEXT
    )''')

    c.execute('''CREATE TABLE IF NOT EXISTS request_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip TEXT, method TEXT, path TEXT, payload TEXT,
        verdict TEXT, attack_type TEXT, matched_rule TEXT, timestamp TEXT
    )''')

    c.execute('''CREATE TABLE IF NOT EXISTS products (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT, price REAL, description TEXT
    )''')

    c.execute('''CREATE TABLE IF NOT EXISTS shop_users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE, password TEXT
    )''')

    c.execute('''CREATE TABLE IF NOT EXISTS feedback (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT, message TEXT, created_at TEXT
    )''')

    count = c.execute('SELECT COUNT(*) FROM products').fetchone()[0]
    if count == 0:
        c.executemany('INSERT INTO products (name, price, description) VALUES (?, ?, ?)', [
            ('Wireless Mouse', 799.00, 'Ergonomic 2.4GHz wireless mouse'),
            ('Mechanical Keyboard', 3499.00, 'RGB backlit mechanical keyboard'),
            ('USB-C Hub', 1299.00, '7-in-1 USB-C hub with HDMI'),
            ('Laptop Stand', 899.00, 'Adjustable aluminium laptop stand'),
            ('Webcam HD', 2199.00, '1080p HD webcam with mic'),
        ])

    count = c.execute('SELECT COUNT(*) FROM shop_users').fetchone()[0]
    if count == 0:
        c.execute("INSERT INTO shop_users (username, password) VALUES (?, ?)",
                  ('admin', 'admin123'))
        c.execute("INSERT INTO shop_users (username, password) VALUES (?, ?)",
                  ('john', 'john@2024'))

    conn.commit()
    conn.close()
    print("[WAF] Database initialized at", DB_PATH)


@app.before_request
def run_waf():
    skip = ['/dashboard', '/traffic', '/inspector', '/terminal',
            '/signup', '/logout', '/waf-control', '/toggle-waf', '/reset-brute-force']
    if request.path.startswith('/static') or request.path in skip:
        return None

    if not WAF_STATE['enabled']:
        log_request(request.remote_addr, request.method, request.path,
                    request.full_path, 'ALLOWED (WAF OFF)', None, None)
        return None

    attack_type, matched_rule = waf_check()

    if attack_type:
        return render_template(
            'blocked.html',
            attack_type=attack_type,
            matched_rule=matched_rule,
            full_path=request.full_path,
            method=request.method,
            path=request.path,
            query=request.query_string.decode('utf-8', errors='ignore'),
            headers=dict(request.headers),
            ip=request.remote_addr
        ), 403

    return None


def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get('user_id'):
            flash('Please log in first.', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return wrapper


# -------------------------------------------------------------------
# WAF Control Panel
# -------------------------------------------------------------------
@app.route('/')
def home():
    return render_template('home.html', waf_enabled=WAF_STATE['enabled'])


@app.route('/waf-control')
def waf_control():
    return render_template('waf_control.html', waf_enabled=WAF_STATE['enabled'])


@app.route('/toggle-waf', methods=['POST'])
def toggle_waf():
    WAF_STATE['enabled'] = not WAF_STATE['enabled']
    status = "ENABLED" if WAF_STATE['enabled'] else "DISABLED"
    flash(f'WAF is now {status}.', 'success')
    return redirect(url_for('waf_control'))


@app.route('/reset-brute-force', methods=['POST'])
def reset_brute_force_route():
    reset_brute_force()
    flash('Brute force counter reset. You can now demo attacks again.', 'success')
    return redirect(url_for('waf_control'))


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        if len(password) < 8:
            flash('Password must be at least 8 characters.', 'error')
            return redirect(url_for('signup'))
        conn = get_db()
        try:
            conn.execute(
                'INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)',
                (username, generate_password_hash(password), datetime.now().isoformat())
            )
            conn.commit()
            flash('Account created! Please log in.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username already taken.', 'error')
        finally:
            conn.close()
    return render_template('signup.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        conn = get_db()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()
        if user and check_password_hash(user['password_hash'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            FAILED_LOGINS[request.remote_addr] = 0
            flash('Logged in successfully.', 'success')
            return redirect(url_for('home'))
        else:
            ip = request.remote_addr
            FAILED_LOGINS[ip] = FAILED_LOGINS.get(ip, 0) + 1
            flash(f'Invalid credentials. Attempts: {FAILED_LOGINS[ip]}/{BRUTE_FORCE_THRESHOLD}', 'error')
    return render_template('login.html')


@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out.', 'success')
    return redirect(url_for('home'))


@app.route('/dashboard')
def dashboard():
    conn = get_db()
    logs = conn.execute('SELECT * FROM attack_logs ORDER BY timestamp DESC LIMIT 100').fetchall()
    total_attacks = conn.execute('SELECT COUNT(*) FROM attack_logs').fetchone()[0]
    sqli = conn.execute("SELECT COUNT(*) FROM attack_logs WHERE attack_type='SQL Injection'").fetchone()[0]
    xss = conn.execute("SELECT COUNT(*) FROM attack_logs WHERE attack_type='XSS'").fetchone()[0]
    traversal = conn.execute("SELECT COUNT(*) FROM attack_logs WHERE attack_type='Path Traversal'").fetchone()[0]
    bruteforce = conn.execute("SELECT COUNT(*) FROM attack_logs WHERE attack_type='Brute Force'").fetchone()[0]
    conn.close()
    return render_template('dashboard.html', logs=logs, total_attacks=total_attacks,
                           sqli=sqli, xss=xss, traversal=traversal, bruteforce=bruteforce,
                           waf_enabled=WAF_STATE['enabled'])


@app.route('/traffic')
def traffic():
    conn = get_db()
    rows = conn.execute('SELECT * FROM request_log ORDER BY timestamp DESC LIMIT 200').fetchall()
    blocked = conn.execute("SELECT COUNT(*) FROM request_log WHERE verdict LIKE 'BLOCKED%'").fetchone()[0]
    allowed = conn.execute("SELECT COUNT(*) FROM request_log WHERE verdict LIKE 'ALLOWED%'").fetchone()[0]
    conn.close()
    return render_template('traffic.html', rows=rows, blocked=blocked, allowed=allowed)


@app.route('/inspector', methods=['GET', 'POST'])
def inspector():
    result = None
    if request.method == 'POST':
        payload = request.form.get('payload', '')
        attack_type, matched_rule = inspect(payload)
        result = {'payload': payload,
                  'verdict': 'BLOCKED' if attack_type else 'ALLOWED',
                  'attack_type': attack_type, 'matched_rule': matched_rule}
    return render_template('inspector.html', result=result)


@app.route('/terminal', methods=['GET', 'POST'])
def terminal():
    output = None
    if request.method == 'POST':
        cmd = request.form.get('command', '').strip()
        output = simulate_curl(cmd)
    return render_template('terminal.html', output=output)


def simulate_curl(cmd):
    if not cmd or not cmd.strip():
        return {'error': 'Please enter a command.'}

    attack_type, matched_rule = inspect(cmd)

    import re
    url_match = re.search(r'https?://[^\s"\']+', cmd)
    url = url_match.group(0) if url_match else cmd

    from urllib.parse import urlparse
    try:
        parsed = urlparse(url)
        path = parsed.path or '/'
        query = parsed.query or ''
    except Exception:
        path = url
        query = ''

    log_request('127.0.0.1 (terminal)', 'GET', path, cmd,
                'BLOCKED' if attack_type else 'ALLOWED', attack_type, matched_rule)

    return {
        'command': cmd, 'url': url, 'path': path, 'query': query,
        'verdict': 'BLOCKED' if attack_type else 'ALLOWED',
        'attack_type': attack_type, 'matched_rule': matched_rule,
    }


@app.route('/clear-logs', methods=['POST'])
def clear_logs():
    conn = get_db()
    conn.execute('DELETE FROM attack_logs')
    conn.execute('DELETE FROM request_log')
    conn.commit()
    conn.close()
    flash('All logs cleared.', 'success')
    return redirect(url_for('dashboard'))


# ===================================================================
# TARGET WEB APPLICATION (ShopEase)
# ===================================================================

@app.route('/site/')
def site_home():
    conn = get_db()
    products = conn.execute('SELECT * FROM products').fetchall()
    feedback_list = conn.execute('SELECT * FROM feedback ORDER BY id DESC LIMIT 5').fetchall()
    conn.close()
    return render_template('target_home.html', products=products,
                           feedback_list=feedback_list, waf_enabled=WAF_STATE['enabled'])


@app.route('/site/search')
def site_search():
    query = request.args.get('q', '')
    conn = get_db()

    if not WAF_STATE['enabled']:
        if "' or " in query.lower() or " or 1=1" in query.lower() or "union" in query.lower():
            products = conn.execute('SELECT * FROM products').fetchall()
            users = conn.execute('SELECT username, password FROM shop_users').fetchall()
            conn.close()
            return render_template('target_search.html',
                                   query=query, products=products,
                                   users=users, sqli_success=True,
                                   waf_enabled=False)
    products = conn.execute(
        "SELECT * FROM products WHERE name LIKE ?", (f"%{query}%",)
    ).fetchall()
    conn.close()
    return render_template('target_search.html', query=query, products=products,
                           sqli_success=False, waf_enabled=WAF_STATE['enabled'])


@app.route('/site/product/<int:pid>')
def site_product(pid):
    conn = get_db()
    product = conn.execute('SELECT * FROM products WHERE id = ?', (pid,)).fetchone()
    conn.close()
    if not product:
        return "Product not found", 404
    return render_template('target_product.html', product=product,
                           waf_enabled=WAF_STATE['enabled'])


@app.route('/site/login', methods=['GET', 'POST'])
def site_login():
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')

        conn = get_db()

        if not WAF_STATE['enabled']:
            if ("' or " in username.lower() or
                " or 1=1" in username.lower() or
                "' or '1'='1" in username.lower()):
                user = conn.execute('SELECT * FROM shop_users LIMIT 1').fetchone()
                conn.close()
                session['site_user'] = user['username']
                session['site_login_method'] = 'SQL Injection'
                flash(f"⚠️ SQL Injection SUCCESSFUL! Logged in as '{user['username']}' without password.", 'error')
                return redirect(url_for('site_home'))

        user = conn.execute(
            'SELECT * FROM shop_users WHERE username = ? AND password = ?',
            (username, password)
        ).fetchone()
        conn.close()

        if user:
            session['site_user'] = username
            session['site_login_method'] = 'Normal'
            FAILED_LOGINS[request.remote_addr] = 0
            flash(f"✅ Welcome back, {username}!", 'success')
            return redirect(url_for('site_home'))
        else:
            ip = request.remote_addr
            FAILED_LOGINS[ip] = FAILED_LOGINS.get(ip, 0) + 1
            flash(f"❌ Invalid credentials. Attempts: {FAILED_LOGINS[ip]}/{BRUTE_FORCE_THRESHOLD}", 'error')

    return render_template('target_login.html', waf_enabled=WAF_STATE['enabled'])


@app.route('/site/logout')
def site_logout():
    session.pop('site_user', None)
    session.pop('site_login_method', None)
    flash('Logged out of ShopEase.', 'success')
    return redirect(url_for('site_home'))


@app.route('/site/feedback', methods=['GET', 'POST'])
def site_feedback():
    conn = get_db()
    if request.method == 'POST':
        name = request.form.get('name', '')
        msg = request.form.get('message', '')
        conn.execute('INSERT INTO feedback (name, message, created_at) VALUES (?, ?, ?)',
                     (name, msg, datetime.now().isoformat()))
        conn.commit()
    feedback_list = conn.execute('SELECT * FROM feedback ORDER BY id DESC LIMIT 20').fetchall()
    conn.close()
    return render_template('target_feedback.html',
                           feedback_list=feedback_list,
                           waf_enabled=WAF_STATE['enabled'])


# -------------------------------------------------------------------
# Run
# -------------------------------------------------------------------
# Run init_db() on module import (works under Gunicorn too)
init_db()

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)