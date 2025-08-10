import os
from flask import Flask, render_template, redirect, url_for, flash
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

app = Flask(__name__)
app.config.from_object('config.Config')

db.init_app(app)
csrf = CSRFProtect(app)

login_manager = LoginManager(app)
login_manager.login_view = 'login'

limiter = Limiter(key_func=get_remote_address, default_limits=["200 per day", "50 per hour"])
limiter.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.before_first_request
def create_tables():
    db.create_all()
    admin = User.query.filter_by(username="admin").first()
    if not admin:
        hashed_pw = generate_password_hash("admin123", method='sha256')
        admin = User(username="admin", password=hashed_pw, is_admin=True)
        db.session.add(admin)
        db.session.commit()


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.email.data).first()
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
        target_ip = form.target.data.strip()
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

        thread = Thread(target=scan_ports_thread, args=(new_scan.id,))
        thread.daemon = True
        thread.start()

        flash(f"Scan started for {target_ip} ports {start_port}-{end_port}", "success")
        return redirect(url_for('index'))

    return render_template('scan.html', form=form)


if __name__ == '__main__':
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
