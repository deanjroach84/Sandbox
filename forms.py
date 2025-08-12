from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, IntegerField
from wtforms.validators import DataRequired, Length, EqualTo, Email, IPAddress, NumberRange

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=30)])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=30)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password', message='Passwords must match')])
    submit = SubmitField('Register')

class ScanForm(FlaskForm):
    target_ip = StringField('Target IP', validators=[DataRequired(), IPAddress(ipv4=True, message="Invalid IPv4 address")])
    start_port = IntegerField('Start Port', validators=[DataRequired(), NumberRange(min=1, max=65535, message="Port must be between 1 and 65535")])
    end_port = IntegerField('End Port', validators=[DataRequired(), NumberRange(min=1, max=65535, message="Port must be between 1 and 65535")])
    submit = SubmitField('Start Scan')

class AdminAddUserForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=30)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    submit = SubmitField('Add User')
