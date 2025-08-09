#config.py

import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'change_this_to_a_random_secret'
    SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(os.path.dirname(__file__), 'instance', 'app.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False

RECAPTCHA_PUBLIC_KEY = 'your-public-key-here'
RECAPTCHA_PRIVATE_KEY = 'your-private-key-here'

WTF_CSRF_SECRET_KEY = os.environ.get('CSRF_SECRET_KEY') or 'a-very-secret-string'