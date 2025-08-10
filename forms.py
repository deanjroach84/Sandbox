from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, IntegerField, SubmitField
from wtforms.validators import DataRequired, Length, Email, EqualTo, NumberRange

class LoginForm(FlaskForm):
    email = StringField(
        'Email',
        validators=[DataRequired(), Email(message='Invalid email address')]
    )
    password = PasswordField(
        'Password',
        validators=[DataRequired()]
    )
    submit = SubmitField('Login')


class RegisterForm(FlaskForm):
    username = StringField(
        'Username',
        validators=[DataRequired(), Length(min=3, max=25)]
    )
    email = StringField(
        'Email',
        validators=[DataRequired(), Email()]
    )
    password = PasswordField(
        'Password',
        validators=[DataRequired(), Length(min=6)]
    )
    confirm_password = PasswordField(
        'Confirm Password',
        validators=[DataRequired(), EqualTo('password')]
    )
    submit = SubmitField('Register')


class ScanForm(FlaskForm):
    target = StringField(
        'Target IP or Domain',
        validators=[DataRequired()]
    )
    start_port = IntegerField(
        'Start Port',
        validators=[DataRequired(), NumberRange(min=1, max=65535)]
    )
    end_port = IntegerField(
        'End Port',
        validators=[DataRequired(), NumberRange(min=1, max=65535)]
    )
    submit = SubmitField('Start Scan')
