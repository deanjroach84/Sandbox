# forms.py

from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, IntegerField
from wtforms.validators import DataRequired, Length, EqualTo

# ------------------------
# Login Form
# ------------------------
class LoginForm(FlaskForm):
    username = StringField(
        'Username',
        validators=[DataRequired(), Length(min=3, max=30)]
    )
    password = PasswordField(
        'Password',
        validators=[DataRequired()]
    )
    submit = SubmitField('Login')

# ------------------------
# Registration Form
# ------------------------
class RegisterForm(FlaskForm):
    username = StringField(
        'Username',
        validators=[DataRequired(), Length(min=3, max=30)]
    )
    password = PasswordField(
        'Password',
        validators=[DataRequired()]
    )
    confirm_password = PasswordField(
        'Confirm Password',
        validators=[DataRequired(), EqualTo('password')]
    )
    submit = SubmitField('Register')

# ------------------------
# Scan Form
# ------------------------
class ScanForm(FlaskForm):
    target_ip = StringField(
        'Target IP',
        validators=[DataRequired()]
    )
    start_port = IntegerField(
        'Start Port',
        validators=[DataRequired()]
    )
    end_port = IntegerField(
        'End Port',
        validators=[DataRequired()]
    )
    submit = SubmitField('Start Scan')
