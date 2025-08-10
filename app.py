#app.py

import os
import sqlite3
from flask import Flask, render_template, redirect, url_for, flash, request, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import generate_password_hash, check_password_hash
from forms import LoginForm, RegisterForm, ScanForm
from network_utils import run_scan, dns_lookup, reverse_ip_lookup, traceroute, whois_lookup, subdomain_enum
from io import BytesIO
import csv
import json
from fpdf import FPDF

# Flask app initialization
app = Flask(__name__)
app.config.from_object('config.Config')

# Database
db = SQLAlchemy(app)

# CSRF
csrf = CSRFProtect(app)

# Login manager
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Limiter
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)
limiter.init_app(app)


# MODELS
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)


class ScanHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    target = db.Column(db.String(255), nullable=False)
    result = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))


# LOGIN LOADER
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# Ensure admin exists
@app.before_first_request
def create_tables():
    db.create_all()
    admin = User.query.filter_by(username="admin").first()
    if not admin:
        hashed_pw = generate_password_hash("admin123", method='sha256')
        admin = User(username="admin", password=hashed_pw, is_admin=True)
        db.session.add(admin)
        db.session.commit()


# ROUTES
@app.route('/')
def index():
    return render_template('index.html')


@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user)
            return redirect(url_for('index'))
        flash("Invalid credentials", "danger")
    return render_template('login.html', form=form)


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_pw = generate_password_hash(form.password.data, method='sha256')
        new_user = User(username=form.username.data, password=hashed_pw)
        db.session.add(new_user)
        db.session.commit()
        flash("Account created successfully!", "success")
        return redirect(url_for('login'))
    return render_template('register.html', form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/scan', methods=['GET', 'POST'])
@login_required
def scan():
    form = ScanForm()
    if form.validate_on_submit():
        target = form.target.data
        scan_type = form.scan_type.data
        result = ""

        if scan_type == "port":
            result = run_scan(target)
        elif scan_type == "dns":
            result = dns_lookup(target)
        elif scan_type == "reverse":
            result = reverse_ip_lookup(target)
        elif scan_type == "traceroute":
            result = traceroute(target)
        elif scan_type == "whois":
            result = whois_lookup(target)
        elif scan_type == "subdomain":
            result = subdomain_enum(target)

        history = ScanHistory(target=target, result=str(result), user_id=current_user.id)
        db.session.add(history)
        db.session.commit()

        return render_template('scan_history.html', scans=[history])
    return render_template('index.html', form=form)


@app.route('/scan_history')
@login_required
def scan_history():
    scans = ScanHistory.query.filter_by(user_id=current_user.id).all()
    return render_template('scan_history.html', scans=scans)


@app.route('/admin')
@login_required
def admin():
    if not current_user.is_admin:
        flash("Access denied", "danger")
        return redirect(url_for('index'))
    users = User.query.all()
    return render_template('admin.html', users=users)


@app.route('/delete_user/<int:user_id>')
@login_required
def delete_user(user_id):
    if not current_user.is_admin:
        flash("Access denied", "danger")
        return redirect(url_for('index'))
    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    flash("User deleted", "success")
    return redirect(url_for('admin'))


if __name__ == '__main__':
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
