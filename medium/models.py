#Represents something and stores it in the DB
import base64
import os
from datetime import datetime
from io import BytesIO

import onetimepass
import pyqrcode
from flask import current_app
from flask_login import UserMixin  # For the users sessions
from itsdangerous import JSONWebSignatureSerializer as InfinitSerializer
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from medium import db, login_manager


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(25), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    image_file = db.Column(db.String(20), nullable=False, default='default.jpg')
    password = db.Column(db.String(60), nullable=False)
    registration_date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    ciphered_Uk = db.Column(db.String(32), nullable=False)
    salt_Pk = db.Column(db.String(16), nullable=False)
    iv_Uk = db.Column(db.String(16), nullable=False)
    otp_secret = db.Column(db.String(16))
    confirmed = db.Column(db.Boolean, nullable=False, default=False)
    posts = db.relationship('Post', cascade="all,delete", backref='author', lazy=True)
    devices = db.relationship('Device', cascade="all,delete", backref='belong', lazy=True)

    ##Para 2FA
    def __init__(self, **kwargs):
        super(User, self).__init__(**kwargs)
        if self.otp_secret is None:
            # generate a random secret
            self.otp_secret = base64.b32encode(os.urandom(10)).decode('utf-8')

    def get_totp_uri(self):
        return 'otpauth://totp/2FA-Demo:{0}?secret={1}&issuer=2FA-Demo' \
            .format(self.username, self.otp_secret)

    def verify_totp(self, token):
        return onetimepass.valid_totp(token, self.otp_secret)

    #Para generar tokens para resetear la contraseña
    def get_reset_token(self, expiration=180):
        s = Serializer(current_app.config['SECRET_KEY'], expiration)
        return s.dumps({'user_id': self.id}).decode('utf-8')#Esto nos devuelve el token a partir de la clave secreta, para ello le 
        #pasamos como payload un identificador en este caso un diccionario con el id del usuario, que mas tarde mediante loads, sera 
        # decodifiaco de nuevo


    #Para comprobar la validez del token
    @staticmethod
    def verify_reset_token(token):
        s = Serializer(current_app.config['SECRET_KEY'])#Cargamos el objeto Serializer
        try:
            user_id = s.loads(token)['user_id']#Comprobamos que el token es correcto y no ha expirado
        except:
            return None
        return User.query.get(user_id)

    def __repr__(self):
        return f"User('{self.username}', with email '{self.email}', and photo '{self.image_file}')"

class Device(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    addr = db.Column(db.String(16), nullable=False)
    browser = db.Column(db.String(40), nullable=True)
    so = db.Column(db.String(40), nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    date_posted = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    content = db.Column(db.Text, nullable=False)
    #Por defecto privado, para mejorar la privacidad
    post_type = db.Column(db.String(1), nullable=False, default='0')
    shared_token = db.Column(db.String(512), nullable=True)#Por defecto, default=NULL
    iv_post = db.Column(db.String(16), nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def get_shared_token(self):
        s = InfinitSerializer(current_app.config['SECRET_KEY'])
        return s.dumps({'post_id': self.id}).decode('utf-8')#Esto nos devuelve el token a partir de la clave secreta, para ello le 
        #pasamos como payload un identificador en este caso un diccionario con el id del usuario, que mas tarde mediante loads, sera 
        # decodifiaco de nuevo
    '''
    def get_post_type(self):
        return self.__post_type

    def set_post_type(self, post_type):
        self.__post_type = post_type
    '''

    @staticmethod
    def verify_shared_token(token):
        s = InfinitSerializer(current_app.config['SECRET_KEY'])#Cargamos el objeto Serializer
        try:
            post_id = s.loads(token)['post_id']#Comprobamos que el token es correcto y no ha expirado
        except:
            return None
        return Post.query.get(post_id)

    def __repr__(self):
        return f"Post('{self.title}', posted at '{self.date_posted}')"
