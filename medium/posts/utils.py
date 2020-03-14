
from medium.users.utils import (aes_cbc_encrypt, aes_cbc_decrypt)
import secrets
from flask import current_app
from medium.models import Post

def create_personal_post(Pk, user, postForm):

    Uk = aes_cbc_decrypt(user.ciphered_Uk, Pk, user.iv_Uk)
    iv_post = secrets.token_bytes(16)
    #current_app.logger.warning('[DESCIFRADO: secret_key %s] PK %s Iv %s]',current_user.secret_key, Pk, iv_user)
    cipher_title = aes_cbc_encrypt(postForm.title.data.encode(), Uk, iv_post)
    cipher_content = aes_cbc_encrypt(postForm.content.data.encode(), Uk, iv_post)
    post = Post(title = cipher_title,
                content = cipher_content,
                post_type = postForm.post_type.data,
                iv_post = iv_post,
                author = user)
    return post

def update_personal_post(Pk, user, post, postForm):

    Uk = aes_cbc_decrypt(user.ciphered_Uk, Pk, user.iv_Uk)
    iv_post = secrets.token_bytes(16)
    #current_app.logger.warning('[DESCIFRADO: secret_key %s] PK %s Iv %s]',current_user.secret_key, Pk, iv_user)
    post.title = aes_cbc_encrypt(postForm.title.data.encode(), Uk, iv_post)
    post.content = aes_cbc_encrypt(postForm.content.data.encode(), Uk, iv_post)
    post.post_type = postForm.post_type.data
    post.iv_post = iv_post


def decrypt_personal_post(Pk, user, post):
    Uk = aes_cbc_decrypt(user.ciphered_Uk, Pk, user.iv_Uk)
    plain_title = aes_cbc_decrypt(post.title, Uk, post.iv_post)
    plain_content = aes_cbc_decrypt(post.content, Uk, post.iv_post)
    post.title = plain_title.decode('utf-8')
    post.content = plain_content.decode('utf-8')
