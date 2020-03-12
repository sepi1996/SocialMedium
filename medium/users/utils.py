import os
import secrets
from flask_mail import Message
from PIL import Image
from flask import url_for, current_app
from medium import mail
from medium.models import Device
from medium import   db




def send_reset_email(user):
    token = user.get_reset_token(expiration=1800)
    msg = Message('Password Reset for Social Medium',
                sender='noreply@das.com', recipients=[user.email])
    msg.body = f'''To reset your password, visit the following link: <b>hola</b>
{url_for('users.reset_token', token=token, _external=True)}
If you did not make this request then simply ignore this email and no changes will be made.
'''
    mail.send(msg)



def createDevice(user, request):
    device = Device(addr = request.remote_addr,
                    browser = request.user_agent.browser,
                    so = request.user_agent.platform,
                    belong = user)
    db.session.add(device)
    db.session.commit()

def checkUserDevice(user, request):
    device = Device.query.filter_by(addr=request.remote_addr)\
        .filter_by(belong=user).filter_by(browser=request.user_agent.browser).filter_by(so=request.user_agent.platform).first()
    if device is None:
        return False
    else:
        return True    


def send_confirmation_email(user):
    token = user.get_reset_token(expiration=3600)
    msg = Message('Account Activation for Social Medium',
                sender='noreply@das.com', recipients=[user.email])
    msg.body = f'''To activate your account, visit the following link:<b>hola</b>
{url_for('users.account_activation', token=token, _external=True)}
If you did not make this request then simply ignore this email and no changes will be made.
'''
    mail.send(msg)    


def save_picture(form_picture):
    randomHex = secrets.token_hex(8)
    _, fileExt = os.path.splitext(form_picture.filename)#El primero es _ porque no queremos almacenar ese valor devuleto por la funcion
    pictureFilename = randomHex + fileExt
    picturePath = os.path.join(current_app.root_path, 'static/profilePictures', pictureFilename)
    #Redimensionamos la imagem, para no almazenar imagenes grandes que ocupan mas, sin ser necesario
    size = (115, 115)
    newImage = Image.open(form_picture)
    newImage.thumbnail(size)
    newImage.save(picturePath)

    return pictureFilename

def deleteUsersPosts(user):
    pass