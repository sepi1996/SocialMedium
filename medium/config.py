import os
import json
#from datetime import timedelta

with open('/etc/config.json') as config_file:
    config = json.load(config_file)


class Config:
    SECRET_KEY = config.get('SECRET_KEY')

    SQLALCHEMY_DATABASE_URI = 'sqlite:///medium.db'
    MAIL_SERVER = 'smtp.googlemail.com'
    MAIL_PORT = 587
    MAIL_USE_TLS = True

    MAIL_USERNAME = config.get('MAIL_USERNAME')
    MAIL_PASSWORD = config.get('MAIL_PASSWORD')

    RECAPTCHA_PUBLIC_KEY = config.get('RECAPTCHA_PUBLIC_KEY')
    RECAPTCHA_PRIVATE_KEY = config.get('RECAPTCHA_PRIVATE_KEY')
    #REMEMBER_COOKIE_DURATION = timedelta(minutes=1)

