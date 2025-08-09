#app.py

import os
import socket
import threading
import uuid
from flask import (
    Flask, render_template, request, session,
    redirect, url_for, jsonify, flash
)
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from datetime import timedelta
from models import db, User, Scan
from forms import LoginForm, RegisterForm, ForgotPasswordForm
from network_utils import scan_ports_thread

# --- Flask app setup ---
app = Flask(__name__, static_folder='static')
app.config.from_object('config.Config')

csrf = CSRFProtect(app)
db.init_app(app)

limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

# Session timeout config
@app.before_request
def make_session_permanent():
    session.permanent = True
    app.permanent_session_lifetime = timedelta(minutes=30)

# --- Helper functions ---
def current_user():
    if 'user_id' in session:
        return User.query.get(session['user_id'])
    return None

def login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user():
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        user = current_user()
        if not user or not user.is_admin:
            flash("Admin access required.", "danger")
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated

# --- Routes ---

@app.route('/')
@login_required
def index():
    return render_template('index.html', user=current_user())

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    if current_user():
        return redirect(url_for('index'))

    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data.strip()).first()
        if user and check_password_hash(user.password, form.password.data):
            session['user_id'] = user.id
            flash("Logged in successfully.", "success")
            return redirect(url_for('index'))
        else:
            flash("Invalid username or password.", "danger")
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        existing = User.query.filter_by(username=form.username.data.strip()).first()
        if existing:
            flash("Username already exists.", "danger")
        else:
            new_user = User(
                username=form.username.data.strip(),
                password=generate_password_hash(form.password.data),
                is_admin=False
            )
            db.session.add(new_user)
            db.session.commit()
            flash("Registration successful! Please log in.", "success")
            return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    form = ForgotPasswordForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data.strip()).first()
        if not user:
            flash("Username not found.", "danger")
            return redirect(url_for('forgot_password'))
        user.password = generate_password_hash(form.new_password.data)
        db.session.commit()
        flash("Password updated successfully! Please login.", "success")
        return redirect(url_for('login'))
    return render_template('forgot_password.html', form=form)

# --- Admin interface ---

@app.route('/admin')
@login_required
@admin_required
def admin():
    users = User.query.all()
    return render_template('admin.html', users=users, current_user=current_user())

@app.route('/admin/users/delete/<int:user_id>', methods=['POST'])
@login_required
@admin_required
@csrf.exempt
def admin_delete_user(user_id):
    user = User.query.get(user_id)
    if not user:
        flash("User not found.", "danger")
        return redirect(url_for('admin'))
    if user.is_admin:
        flash("Cannot delete admin user.", "danger")
        return redirect(url_for('admin'))

    db.session.delete(user)
    db.session.commit()
    flash("User deleted successfully.", "success")
    return redirect(url_for('admin'))

# --- Scanning logic ---

active_scans = {}

@app.route('/start_scan', methods=['POST'])
@login_required
@csrf.exempt
def start_scan():
    data = request.get_json() or request.form
    target_ip = data.get('ip') or data.get('target_ip')
    ports = data.get('ports')

    try:
        start_port = 1
        end_port = int(ports) if ports else 100
    except Exception:
        return jsonify({'error': 'Invalid ports parameter'}), 400

    if not target_ip:
        return jsonify({'error': 'No target IP provided'}), 400

    scan = Scan(
        user_id=current_user().id,
        target_ip=target_ip,
        start_port=start_port,
        end_port=end_port,
        open_ports=""
    )
    db.session.add(scan)
    db.session.commit()

    scan_id = str(scan.id)
    thread = threading.Thread(target=scan_ports_thread, args=(scan_id,))
    active_scans[scan_id] = thread
    thread.start()

    return jsonify({'scan_id': scan_id})

@app.route('/scan_status/<scan_id>')
@login_required
def scan_status(scan_id):
    scan = Scan.query.get(scan_id)
    if not scan or scan.user_id != current_user().id:
        return jsonify({'error': 'Scan not found or unauthorized'}), 404

    import json
    try:
        open_ports_list = json.loads(scan.open_ports) if scan.open_ports else []
    except Exception:
        open_ports_list = []

    total_ports = scan.end_port - scan.start_port + 1
    done = not (scan_id in active_scans and active_scans[scan_id].is_alive())

    progress = 100 if done else 0

    results = [[port, get_service_name(port)] for port in open_ports_list]

    return jsonify({
        'progress': progress,
        'done': done,
        'results': results
    })

@app.route('/stop_scan/<scan_id>', methods=['POST'])
@login_required
@csrf.exempt
def stop_scan(scan_id):
    if scan_id in active_scans:
        active_scans.pop(scan_id, None)
        flash("Scan stopped.", "info")
        return jsonify({'message': 'Scan stopped.'})

    return jsonify({'error': 'Scan ID not found'}), 404

# --- Helper functions ---

def get_service_name(port):
    common_services = {
        20: 'FTP Data', 21: 'FTP Control', 22: 'SSH', 23: 'Telnet',
        25: 'SMTP', 53: 'DNS', 80: 'HTTP', 110: 'POP3',
        143: 'IMAP', 443: 'HTTPS', 3306: 'MySQL', 3389: 'RDP',
        5900: 'VNC', 8080: 'HTTP Proxy'
    }
    return common_services.get(port, "Open")

# --- Main entry ---
if __name__ == '__main__':
    with app.app_context():
        db.create_all()

        # Create default admin user if not exists
        admin_user = User.query.filter_by(username='admin').first()
        if not admin_user:
            admin_user = User(
                username='admin',
                password=generate_password_hash('admin123'),  # Change password after first login!
                is_admin=True
            )
            db.session.add(admin_user)
            db.session.commit()
            print("Default admin user created: username='admin', password='admin123'")

    port = int(os.environ.get('PORT', 10000))
    app.run(host='0.0.0.0', port=port)