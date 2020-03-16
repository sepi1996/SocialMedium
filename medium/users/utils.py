import os
import secrets
from flask_mail import Message
from PIL import Image
from flask import url_for, current_app
from medium import mail
from medium.models import Device
from medium import db

from Crypto.Cipher import AES
from random import randint
from Crypto import Random
from Crypto.Cipher.AES import block_size, key_size
from base64 import b64decode, b64encode
from Crypto.Protocol.KDF import PBKDF2




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
    device = Device(addr = request.headers['X-Real-Ip'],
                    browser = request.user_agent.browser,
                    so = request.user_agent.platform,
                    belong = user)
    db.session.add(device)
    db.session.commit()

def checkUserDevice(user, request):
    device = Device.query.filter_by(addr=request.headers['X-Real-Ip'])\
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










#
#Para el cifrado.
#
def generate_keys(password):
    Uk = secrets.token_bytes(32)
    iv_Uk = secrets.token_bytes(16)
    salt_Pk = secrets.token_bytes(16)
    Pk = PBKDF2(password, salt_Pk, 32, 1000)[0:16]
    ciphered_Uk = aes_cbc_encrypt(Uk, Pk, iv_Uk)
    #PREGUNTAR SI ESTA BIEN
    return ciphered_Uk, salt_Pk, iv_Uk



def aes_ecb_decrypt(data, key):
    """Decrypts the given AES-ECB encrypted data with the given key.
    The un-padding part has been added to support the use that I will make of this
    method on future challenges (for the sake of this challenge it's not needed).
    """
    cipher = AES.new(key, AES.MODE_ECB)
    return pkcs7_unpad(cipher.decrypt(data))


def pkcs7_pad(message, block_size):
    """Pads the given message with the PKCS 7 padding format for the given block size."""
    # If the length of the given message is already equal to the block size, there is no need to pad
    if len(message) == block_size:
        return message
    # Otherwise compute the padding byte and return the padded message
    ch = block_size - len(message) % block_size
    return message + bytes([ch] * ch)


def is_pkcs7_padded(binary_data):
    """Returns whether the data is PKCS 7 padded."""
    # Take what we expect to be the padding
    padding = binary_data[-binary_data[-1]:]
    # Check that all the bytes in the range indicated by the padding are equal to the padding value itself
    return all(padding[b] == len(padding) for b in range(0, len(padding)))


def pkcs7_unpad(data):
    """Unpads the given data from its PKCS 7 padding and returns it."""
    if len(data) == 0:
        raise Exception("The input data must contain at least one byte")
    if not is_pkcs7_padded(data):
        return data
    padding_len = data[len(data) - 1]
    return data[:-padding_len]





def aes_ecb_encrypt(data, key):
    """Encrypts the given data with AES-ECB, using the given key.
    The data is always PKCS 7 padded before being encrypted.
    """
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(pkcs7_pad(data, AES.block_size))


def xor_data(binary_data_1, binary_data_2):
    """Returns the xor of the two binary arrays given."""
    return bytes([b1 ^ b2 for b1, b2 in zip(binary_data_1, binary_data_2)])


def aes_cbc_encrypt(data, key, iv):
    """Encrypts the given data with AES-CBC, using the given key and iv."""
    ciphertext = b''
    prev = iv
    # Process the encryption block by block
    for i in range(0, len(data), AES.block_size):
        # Always PKCS 7 pad the current plaintext block before proceeding
        curr_plaintext_block = pkcs7_pad(data[i:i + AES.block_size], AES.block_size)
        block_cipher_input = xor_data(curr_plaintext_block, prev)
        encrypted_block = aes_ecb_encrypt(block_cipher_input, key)
        ciphertext += encrypted_block
        prev = encrypted_block
    return ciphertext


def aes_cbc_decrypt(data, key, iv, unpad=True):
    """Decrypts the given AES-CBC encrypted data with the given key and iv.
    Returns the unpadded decrypted message when unpad is true, or keeps the plaintext
    padded when unpad is false.
    """
    plaintext = b''
    prev = iv
    # Process the decryption block by block
    for i in range(0, len(data), AES.block_size):
        curr_ciphertext_block = data[i:i + AES.block_size]
        decrypted_block = aes_ecb_decrypt(curr_ciphertext_block, key)
        plaintext += xor_data(prev, decrypted_block)
        prev = curr_ciphertext_block
    # Return the plaintext either unpadded or left with the padding depending on the unpad flag
    return pkcs7_unpad(plaintext) if unpad else plaintext
