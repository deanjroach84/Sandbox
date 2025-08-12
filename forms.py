import re
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, IntegerField
from wtforms.validators import DataRequired, Length, EqualTo, Email, NumberRange, ValidationError


def validate_hostname_or_ip(form, field):
    ip_pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
    hostname_pattern = re.compile(
        r'^(?=.{1,253}$)(?!-)[a-zA-Z0-9-]{1,63}(?<!-)'  # first label
        r'(\.(?!-)[a-zA-Z0-9-]{1,63}(?<!-))*\.?$'       # additional labels and optional trailing dot
    )
    data = field.data.strip()
    if ip_pattern.match(data):
        # Validate IP octets are each 0-255
        octets = data.split('.')
        if any(int(o) > 255 for o in octets):
            raise ValidationError('Invalid IP address.')
    elif not hostname_pattern.match(data):
        raise ValidationError('Invalid hostname or IP address.')


class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=30)])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')


class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=30)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[
        DataRequired(), EqualTo('password', message='Passwords must match')
    ])
    submit = SubmitField('Register')


class ScanForm(FlaskForm):
    target_ip = StringField('Target IP or Hostname', validators=[DataRequired(), validate_hostname_or_ip])
    start_port = IntegerField('Start Port', validators=[
        DataRequired(), NumberRange(min=1, max=65535, message="Port must be between 1 and 65535")
    ])
    end_port = IntegerField('End Port', validators=[
        DataRequired(), NumberRange(min=1, max=65535, message="Port must be between 1 and 65535")
    ])
    submit = SubmitField('Start Scan')


class AdminAddUserForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=30)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    submit = SubmitField('Add User')
