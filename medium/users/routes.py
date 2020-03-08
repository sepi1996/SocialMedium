from flask import Blueprint, render_template, url_for, flash, redirect, request, abort, session
from flask_login import login_user, current_user, logout_user, login_required
from medium import db, bcrypt
from medium.models import User, Post
from medium.users.forms import (RegistrationForm, LoginForm, UpdateAccountForm,
                                   RequestResetForm, ResetPasswordForm)
from medium.users.utils import save_picture, send_reset_email, deleteUsersPosts, send_confirmation_email

from flask import current_app

import onetimepass
import pyqrcode
import os
import base64
import onetimepass
from io import BytesIO

users = Blueprint('users', __name__)

@users.route("/register", methods=['GET', 'POST'])
def register():

    if current_user.is_authenticated:
        return redirect(url_for('main.home'))
    registerForm = RegistrationForm()
    if registerForm.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(registerForm.password.data).decode('utf-8')
        user = User(username = registerForm.username.data,
                    email = registerForm.email.data,
                    password = hashed_password)
        db.session.add(user)
        db.session.commit()
        send_confirmation_email(user)
        flash(f'Your new account has been created! Please verify it within 30 minutes.', 'info')
        # redirect to the two-factor auth page, passing username in session
        session['username'] = user.username
        return redirect(url_for('users.two_factor_setup'))
    return render_template('register.html', title='Register', form=registerForm)

#Para loguerase mediante el usuario y la contraseña. Guarda el estado anterior
@users.route("/login", methods=['GET', 'POST'])
def login():  
    if current_user.is_authenticated:
        return redirect(url_for('main.home'))
    loginForm = LoginForm()
    if loginForm.validate_on_submit():
        user = User.query.filter_by(username=loginForm.username.data).first()
        if user and bcrypt.check_password_hash(user.password, loginForm.password.data):
            '''and user.verify_totp(loginForm.token.data)'''
            if user.confirmed:
                login_user(user, remember=loginForm.remember.data)
                next_page = request.args.get('next')
                if next_page:
                    flash(f'Welcome to Social Medium {user.username}', 'success')
                    current_app.logger.info('El usuario %s se ha logeado', user.username)
                    return redirect(next_page)
                else:
                    flash(f'Welcome to Social Medium {user.username}', 'success')
                    current_app.logger.info('El usuario %s se ha logeado', user.username)
                    return redirect(url_for('main.home'))
            else:
                flash('Please verify your account via email', 'warning')
                current_app.logger.info('Intento de inicio de sesion sin cuenta validad por el usuario %s ', loginForm.username.data)
        else:
            flash('Login Unsuccessful. Please try again', 'warning')
            current_app.logger.warning('Inicio de sesión fallido mediante el usuario %s ', loginForm.username.data)
            current_app.logger.warning('%s  %s %s', request.remote_addr, request.headers.get('User-Agent'), request.cache_control)
    return render_template('login.html', title='Login', form=loginForm)

#Para hacer el logout del actual usuario
@users.route("/logout")
def logout():
    if current_user.is_authenticated:
        current_app.logger.info('El usuario %s ha cerrado sesion', current_user.username)
        logout_user()
    return redirect(url_for('main.home'))


@users.route("/account", methods=['GET', 'POST'])
@login_required
def account():
    accountForm = UpdateAccountForm()
    if accountForm.validate_on_submit():
        if accountForm.picture.data:#Si ha elegido una foto nueva
            pictureFilename = save_picture(accountForm.picture.data)#Primero mediante esta funcion creada la guardamos
            current_user.image_file = pictureFilename#La asociamos en la base de datos
        current_user.username = accountForm.username.data
        current_user.email = accountForm.email.data
        db.session.commit()
        flash(f'Account succesfully updated', 'success')
        return redirect(url_for('users.account'))#Haccemos un redirect para asi hacer una petición tipo GET y no POST
    elif request.method == 'GET':
        accountForm.username.data = current_user.username
        accountForm.email.data = current_user.email
    image_path = url_for('static', filename=f'profilePictures/{current_user.image_file}')
    return render_template('account.html', title='Account', image_path=image_path, form=accountForm)

##Muestra los posts del usuario pasado como parametro
@users.route('/user/<string:username>')
def user_post(username):
    page = request.args.get('page', 1, type=int)
    user = User.query.filter_by(username=username).first_or_404()

    if current_user.is_authenticated:
        posts = Post.query.filter(Post.post_type!='1').filter_by(author=user)\
            .order_by(Post.date_posted.desc()).paginate(page=page, per_page=4)
    else:
        posts = Post.query.filter_by(post_type='2').filter_by(author=user)\
            .order_by(Post.date_posted.desc()).paginate(page=page, per_page=4)
    return render_template('user_post.html', posts = posts, user=user)

@users.route('/user/all/<string:username>')
@login_required
def user_all_post(username):
    user = User.query.filter_by(username=username).first_or_404()
    if user != current_user:
        abort(403)
    page = request.args.get('page', 1, type=int)
    posts = Post.query.filter_by(author=user)\
            .order_by(Post.date_posted.desc()).paginate(page=page, per_page=4)
    return render_template('user_post.html', posts = posts, user=user)

@users.route('/user/public/<string:username>')
@login_required
def user_public_post(username):
    user = User.query.filter_by(username=username).first_or_404()
    if user != current_user:
        abort(403)
    page = request.args.get('page', 1, type=int)
    posts = Post.query.filter_by(post_type='2').filter_by(author=user)\
            .order_by(Post.date_posted.desc()).paginate(page=page, per_page=4)
    return render_template('user_post.html', posts = posts, user=user)

@users.route('/user/personal/<string:username>')
@login_required
def user_personal_post(username):
    user = User.query.filter_by(username=username).first_or_404()
    if user != current_user:
        abort(403)
    page = request.args.get('page', 1, type=int)
    posts = Post.query.filter_by(post_type='1').filter_by(author=user)\
            .order_by(Post.date_posted.desc()).paginate(page=page, per_page=4)
    return render_template('user_post.html', posts = posts, user=user)



@users.route('/user/users/<string:username>')
@login_required
def user_users_post(username):
    user = User.query.filter_by(username=username).first_or_404()
    if user != current_user:
        abort(403)
    page = request.args.get('page', 1, type=int)
    posts = Post.query.filter(Post.post_type!='1').filter(Post.user_id != user.id)\
            .order_by(Post.date_posted.desc()).paginate(page=page, per_page=4)
    return render_template('user_post.html', posts = posts, user=user)

@users.route('/user/private/<string:username>')
@login_required
def user_private_post(username):
    user = User.query.filter_by(username=username).first_or_404()
    if user != current_user:
        abort(403)
    page = request.args.get('page', 1, type=int)
    posts = Post.query.filter_by(post_type='0').filter_by(author=user)\
            .order_by(Post.date_posted.desc()).paginate(page=page, per_page=4)
    return render_template('user_post.html', posts = posts, user=user)


@users.route("/reset_password", methods=['GET', 'POST'])
def reset_request():
    if current_user.is_authenticated:
        flash('You are already logged in, no need to reset the password', 'info')
        return redirect(url_for('main.home'))
    resertForm = RequestResetForm()
    if resertForm.validate_on_submit():
        user = User.query.filter_by(email=resertForm.email.data).first()
        send_reset_email(user)
        flash('An email has been sent to reset your password.', 'info')
        return redirect(url_for('users.login'))
    return render_template('reset_request.html', title='Reset Password', form=resertForm)

@users.route("/reset_password/<token>", methods=['GET', 'POST'])
def reset_token(token):
    if current_user.is_authenticated:
        flash('You are already logged in, no need to reset the password', 'info')
        return redirect(url_for('main.home'))
    user = User.verify_reset_token(token)
    if user is None:
        flash('That is an invalid or expired token', 'danger')
        return redirect(url_for('users.reset_request'))
    passwordResetform = ResetPasswordForm()
    if passwordResetform.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(passwordResetform.password.data).decode('utf-8')
        user.password = hashed_password
        db.session.commit()
        flash('Password Updated!', 'success')
        return redirect(url_for('users.login'))
    return render_template('reset_token.html', title='Reset Password', form=passwordResetform)


@users.route("/account_activation/<token>", methods=['GET', 'POST'])
def account_activation(token):
    if current_user.is_authenticated:
        flash('You are already logged in, no need to activate your account', 'info')
        return redirect(url_for('main.home'))
    user = User.verify_reset_token(token)
    if user is None:
        flash('That is an invalid or expired token', 'danger')
        return redirect(url_for('users.login'))
    else:
        user.confirmed = True
        db.session.commit()
        flash('Account activated. Now you can login into Social Medium', 'success')
        return redirect(url_for('users.login'))


@users.route("/user/<string:username>/delete", methods=['GET','POST'])
@login_required
def delete_user(username):
    user = User.query.filter_by(username=username).first_or_404()
    if user != current_user:
        abort(403)
    #No hace falta tenemos on delete cascade
    #Post.query.filter_by(user_id=user.id).delete()
    logout_user()
    db.session.delete(user)
    db.session.commit()
    
    flash('User deleted!', 'success')
    return redirect(url_for('main.home'))


#QR
@users.route('/qrcode')
def qrcode():
    if 'username' not in session:
        abort(404)
    user = User.query.filter_by(username=session['username']).first()
    if user is None:
        abort(404)

    # for added security, remove username from session
    del session['username']

    # render qrcode for FreeTOTP
    url = pyqrcode.create(user.get_totp_uri())
    stream = BytesIO()
    url.svg(stream, scale=3)
    return stream.getvalue(), 200, {
        'Content-Type': 'image/svg+xml',
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Pragma': 'no-cache',
        'Expires': '0'}

@users.route('/twofactor')
def two_factor_setup():
    if 'username' not in session:
        return redirect(url_for('main.home'))
    user = User.query.filter_by(username=session['username']).first()
    if user is None:
        return redirect(url_for('main.home'))
    # since this page contains the sensitive qrcode, make sure the browser
    # does not cache it
    return render_template('two-factor-setup.html'), 200, {
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Pragma': 'no-cache',
        'Expires': '0'}