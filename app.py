import os
from flask import Flask, render_template, redirect, url_for, flash, request, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import generate_password_hash, check_password_hash
from threading import Thread
import json

from models import db, User, Scan
from forms import LoginForm, RegisterForm, ScanForm
from network_utils import scan_ports_thread

# Ensure 'instance' directory exists before DB init
instance_path = os.path.join(os.path.dirname(__file__), 'instance')
os.makedirs(instance_path, exist_ok=True)

app = Flask(__name__)
app.config.from_object('config.Config')

db.init_app(app)
csrf = CSRFProtect(app)

login_manager = LoginManager(app)
login_manager.login_view = 'login'

limiter = Limiter(key_func=get_remote_address, default_limits=["200 per day", "50 per hour"])
limiter.init_app(app)


def create_tables_and_admin():
    with app.app_context():
        db.create_all()
        admin = User.query.filter_by(username="admin").first()
        if not admin:
            admin = User(username="admin", email="admin@example.com", is_admin=True)
            admin.set_password("admin123")
            db.session.add(admin)
            db.session.commit()

create_tables_and_admin()


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.check_password(form.password.data):
            login_user(user)
            flash("Logged in successfully!", "success")
            return redirect(url_for('index'))
        flash("Invalid credentials", "danger")
    return render_template('login.html', form=form)


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        if User.query.filter_by(username=form.username.data).first():
            flash("Username already taken", "danger")
            return render_template('register.html', form=form)
        if User.query.filter_by(email=form.email.data).first():
            flash("Email already registered", "danger")
            return render_template('register.html', form=form)

        new_user = User(
            username=form.username.data,
            email=form.email.data,
            is_admin=False
        )
        new_user.set_password(form.password.data)
        db.session.add(new_user)
        db.session.commit()
        flash("Account created successfully! Please login.", "success")
        return redirect(url_for('login'))
    return render_template('register.html', form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("Logged out successfully.", "success")
    return redirect(url_for('login'))


@app.route('/scan', methods=['GET', 'POST'])
@login_required
def scan():
    form = ScanForm()
    if form.validate_on_submit():
        target_ip = form.target_ip.data.strip()
        start_port = form.start_port.data
        end_port = form.end_port.data

        if start_port > end_port:
            flash("Start port must be less than or equal to end port.", "danger")
            return render_template('scan.html', form=form)

        new_scan = Scan(
            user_id=current_user.id,
            target_ip=target_ip,
            start_port=start_port,
            end_port=end_port,
            open_ports=json.dumps([])
        )
        db.session.add(new_scan)
        db.session.commit()

        # Start the scanning thread (daemon)
        thread = Thread(target=scan_ports_thread, args=(new_scan.id, app))
        thread.daemon = True
        thread.start()

        flash(f"Scan started for {target_ip} ports {start_port}-{end_port}", "success")
        return redirect(url_for('scan_history'))

    return render_template('scan.html', form=form)


@app.route('/scan_history')
@login_required
def scan_history():
    scans = Scan.query.filter_by(user_id=current_user.id).order_by(Scan.scan_date.desc()).all()
    for scan in scans:
        try:
            scan.open_ports_decoded = json.loads(scan.open_ports)
        except Exception:
            scan.open_ports_decoded = []
    return render_template('scan_history.html', scans=scans)


@app.route('/admin')
@login_required
def admin():
    if not current_user.is_admin:
        abort(403)
    users = User.query.all()
    return render_template('admin.html', users=users)


@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if not current_user.is_admin:
        abort(403)
    user = User.query.get_or_404(user_id)
    if user.is_admin:
        flash("Cannot delete an admin user.", "danger")
        return redirect(url_for('admin'))
    db.session.delete(user)
    db.session.commit()
    flash(f"User {user.username} has been deleted.", "success")
    return redirect(url_for('admin'))


@app.route('/admin/promote_user/<int:user_id>', methods=['POST'])
@login_required
def promote_user(user_id):
    if not current_user.is_admin:
        abort(403)
    user = User.query.get_or_404(user_id)
    if user.is_admin:
        flash(f"User {user.username} is already an admin.", "info")
    else:
        user.is_admin = True
        db.session.commit()
        flash(f"User {user.username} has been promoted to admin.", "success")
    return redirect(url_for('admin'))


if __name__ == '__main__':
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
