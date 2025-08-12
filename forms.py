# app.py
import os
import json
from threading import Thread
from flask import Flask, render_template, redirect, url_for, flash, request, jsonify
from flask_wtf.csrf import CSRFProtect
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import generate_password_hash
from datetime import timedelta

# local imports
from models import db, User, Scan
from forms import LoginForm, RegisterForm, ScanForm
from network_utils import scan_ports_thread  # your thread function

# --- App / config ---
app = Flask(__name__, static_folder="static")
app.config.from_object("config.Config")  # keep config.Config with SECRET_KEY, SQLALCHEMY_DATABASE_URI etc.

# DB init
db.init_app(app)

# CSRF
csrf = CSRFProtect(app)
csrf.init_app(app)

# Login manager
login_manager = LoginManager()
login_manager.login_view = "login"
login_manager.init_app(app)

# Limiter (create then init_app - compatible with newest versions)
limiter = Limiter(key_func=get_remote_address, default_limits=["200 per day", "50 per hour"])
limiter.init_app(app)

# session timeout
@app.before_request
def make_session_permanent():
    session_lifetime = int(os.environ.get("SESSION_TIMEOUT_MINUTES", "30"))
    app.permanent_session_lifetime = timedelta(minutes=session_lifetime)

# loader
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# Ensure tables and default admin exist
@app.before_first_request
def create_tables_and_admin():
    db.create_all()
    admin = User.query.filter_by(username="admin").first()
    if not admin:
        admin = User(username="admin", email="admin@example.com", is_admin=True)
        admin.set_password("admin123")  # change immediately
        db.session.add(admin)
        db.session.commit()
        app.logger.info("Created default admin (username=admin, password=admin123) - change immediately.")


# -------------------------
# Authentication routes
# -------------------------
@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("index"))

    form = RegisterForm()
    if form.validate_on_submit():
        # check username/email collisions
        if User.query.filter((User.username == form.username.data) | (User.email == form.email.data)).first():
            flash("Username or email already exists.", "danger")
            return render_template("register.html", form=form)

        user = User(username=form.username.data.strip(), email=form.email.data.strip())
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash("Registration successful. You may now log in.", "success")
        return redirect(url_for("login"))
    return render_template("register.html", form=form)


@app.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def login():
    if current_user.is_authenticated:
        return redirect(url_for("index"))

    form = LoginForm()
    if form.validate_on_submit():
        identifier = form.identifier.data.strip()
        password = form.password.data

        # detect email vs username
        if "@" in identifier and "." in identifier:
            user = User.query.filter_by(email=identifier).first()
        else:
            user = User.query.filter_by(username=identifier).first()

        if user and user.check_password(password):
            login_user(user)
            flash("Logged in successfully.", "success")
            next_page = request.args.get("next") or url_for("index")
            return redirect(next_page)
        else:
            flash("Invalid username/email or password.", "danger")

    return render_template("login.html", form=form)


@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))


# -------------------------
# Index / Scan routes
# -------------------------
@app.route("/")
@login_required
def index():
    form = ScanForm()
    return render_template("index.html", form=form)


@app.route("/scan", methods=["GET", "POST"])
@login_required
def scan():
    form = ScanForm()
    if form.validate_on_submit():
        target = form.target.data.strip()
        start_port = form.start_port.data
        end_port = form.end_port.data

        if start_port > end_port:
            flash("Start port must be less than or equal to end port.", "danger")
            return render_template("scan.html", form=form)

        scan_record = Scan(
            user_id=current_user.id,
            target_ip=target,
            start_port=start_port,
            end_port=end_port,
            open_ports=json.dumps([])
        )
        db.session.add(scan_record)
        db.session.commit()

        # start background thread (thread reads DB entry by id)
        t = Thread(target=scan_ports_thread, args=(scan_record.id,))
        t.daemon = True
        t.start()

        flash(f"Scan started for {target} ports {start_port}-{end_port}", "success")
        return redirect(url_for("scan_history"))

    return render_template("scan.html", form=form)


@app.route("/scan_history")
@login_required
def scan_history():
    scans = Scan.query.filter_by(user_id=current_user.id).order_by(Scan.scan_date.desc()).all()
    return render_template("scan_history.html", scans=scans)


# -------------------------
# Admin routes
# -------------------------
@app.route("/admin")
@login_required
def admin():
    if not current_user.is_admin:
        flash("Admin access required.", "danger")
        return redirect(url_for("index"))
    users = User.query.all()
    return render_template("admin.html", users=users)


@app.route("/admin/delete_user/<int:user_id>", methods=["POST"])
@login_required
def admin_delete_user(user_id):
    if not current_user.is_admin:
        return jsonify({"error": "Unauthorized"}), 403
    user = User.query.get_or_404(user_id)
    if user.is_admin:
        flash("Cannot delete another admin.", "danger")
        return redirect(url_for("admin"))
    db.session.delete(user)
    db.session.commit()
    flash("User deleted.", "success")
    return redirect(url_for("admin"))


# health-check / ready
@app.route("/health")
def health():
    return jsonify({"status": "ok"}), 200


if __name__ == "__main__":
    # create tables if running locally
    with app.app_context():
        db.create_all()
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)
