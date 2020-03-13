import base64
import os
from io import BytesIO

import onetimepass
import pyqrcode
from flask import (Blueprint, abort, current_app, flash, redirect,
                   render_template, request, session, url_for)
from flask_login import current_user, login_required, login_user, logout_user
from medium import bcrypt, db
from medium.models import Post, User
from medium.users.forms import (ChallengeForm, LoginForm, RegistrationForm,
                                RequestResetForm, ResetPasswordForm,
                                UpdateAccountForm, TokenForm)
from medium.users.utils import (checkUserDevice, createDevice,
                                deleteUsersPosts, save_picture,
                                send_confirmation_email, send_reset_email)

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
        current_app.logger.info('[IP: %s] [Message: El usuario %s se ha registrado]',request.remote_addr, user.username)
        #MIRAR QUE PASA SI HAY ERROR AL CREAR EL DISPOSITIVO
        createDevice(user, request)
        current_app.logger.info('[User: %s] [Message: Ha añadido correctamente un dispositivo de confianza]', user.username)
        send_confirmation_email(user)
        current_app.logger.info('[User: %s] [Message: Ha recibido el correo de confirmacion]', user.username)
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
            if user.confirmed:
                if checkUserDevice(user, request):
                    login_user(user, remember=loginForm.remember.data)
                    next_page = request.args.get('next')
                    if next_page:
                        flash(f'Welcome to Social Medium {user.username}', 'success')
                        current_app.logger.info('[IP: %s] [Message: El usuario %s se ha logeado]',request.remote_addr, user.username)
                        return redirect(next_page)
                    else:
                        flash(f'Welcome to Social Medium {user.username}', 'success')
                        current_app.logger.info('[IP: %s] [Message: El usuario %s se ha logeado]',request.remote_addr, user.username)
                        return redirect(url_for('main.home'))
                else:
                    session['username'] = user.username
                    current_app.logger.info('[IP: %s] Intento de inicio de sesion desde un nuevo dispisitivo, pasamos a token de verifiacion con el usurio %s]', request.remote_addr,loginForm.username.data)
                    return redirect(url_for('users.token',  remember=loginForm.remember.data))
            else:
                flash('Please verify your account via email', 'warning')
                current_app.logger.info('[IP: %s] Intento de inicio de sesion sin cuenta validad por el usuario %s]', request.remote_addr,loginForm.username.data)
        else:
            flash('Login Unsuccessful. Please try again', 'warning')
            current_app.logger.warning('[IP: %s] [Message: Inicio de sesión fallido mediante el usuario %s]', request.remote_addr, loginForm.username.data)
    return render_template('login.html', title='Login', form=loginForm)


@users.route("/token/<string:remember>", methods=['GET', 'POST'])
def token(remember):
    if 'username' not in session:
        current_app.logger.warning('[IP: %s] [Message: Ha intentado introducir el token de sesion directamente]', request.remote_addr)
        abort(403)
    user = User.query.filter_by(username=session['username']).first()
    if user is None:
        current_app.logger.warning('[IP: %s] [Message: Session de usuario no encontrada]', request.remote_addr)
        return redirect(url_for('main.home'))
    tokenform = TokenForm()
    if tokenform.validate_on_submit():
        if user.verify_totp(tokenform.token.data):
            if tokenform.remember.data:
                createDevice(user, request)
                flash(f'Welcome to Social Medium {user.username}. You have added a new trusted device', 'success')
                current_app.logger.info('[User: %s] [Message: Ha añadido correctamente un nuevo dispositivo de confianza]', user.username)
            else:
                flash(f'Welcome to Social Medium {user.username}', 'success')
            del session['username']
            login_user(user, remember=remember)
            current_app.logger.info('[IP: %s] [Message: El usuario %s se ha logeado]',request.remote_addr, user.username)
            return redirect(url_for('main.home'))
        else:
            flash('Login Unsuccessful. Token failure', 'warning')
            current_app.logger.warning('[User: %s] [Message: Ha introducido erroneamente el token de autenticacion]', user.username)
            del session['username']
            return redirect(url_for('main.home'))
    return render_template('token.html', title='Token', form=tokenform)


#Para hacer el logout del actual usuario
@users.route("/logout")
def logout():
    if current_user.is_authenticated:
        current_app.logger.info('[User: %s] [Message: Ha cerrado sesion]', current_user.username)
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
        current_app.logger.info('[User: %s] [Message: Ha modificaco su cuenta]', user.username)
        flash(f'Account succesfully updated', 'success')
        return redirect(url_for('users.account'))#Haccemos un redirect para asi hacer una petición tipo GET y no POST
    elif request.method == 'GET':
        accountForm.username.data = current_user.username
        accountForm.email.data = current_user.email
    image_path = url_for('static', filename=f'profilePictures/{current_user.image_file}')
    return render_template('account.html', title='Account', image_path=image_path, form=accountForm)

##Muestra los posts del usuario pasado como parametro
#Si estas autenticado muestra los privados y publicos
#Si no estas autentiacado, solo muestra los publicos
@users.route('/user/<string:username>')
def user_post(username):
    page = request.args.get('page', 1, type=int)
    user = User.query.filter_by(username=username).first_or_404()

    if current_user.is_authenticated:
        posts = Post.query.filter(Post.post_type!='1').filter_by(author=user)\
            .order_by(Post.date_posted.desc()).paginate(page=page, per_page=4)
        #current_app.logger.info('[User: %s] [Message: Ha intentado acceder ]', user.username)
    else:
        posts = Post.query.filter_by(post_type='2').filter_by(author=user)\
            .order_by(Post.date_posted.desc()).paginate(page=page, per_page=4)
    return render_template('user_post.html', posts = posts, user=user)

#Muestra todos los posts del ususario indicado
@users.route('/user/all/<string:username>')
@login_required
def user_all_post(username):
    user = User.query.filter_by(username=username).first_or_404()
    if user != current_user:
        current_app.logger.warning('[User: %s] [Message: Ha intentado acceder a todos posts de %s]',current_user.username, user.username)
        abort(403)
    page = request.args.get('page', 1, type=int)
    posts = Post.query.filter_by(author=user)\
            .order_by(Post.date_posted.desc()).paginate(page=page, per_page=4)
    return render_template('user_post.html', posts = posts, user=user)

#Muestra todos los posts publicos del ususario indicado
@users.route('/user/public/<string:username>')
@login_required
def user_public_post(username):
    user = User.query.filter_by(username=username).first_or_404()
    page = request.args.get('page', 1, type=int)
    posts = Post.query.filter_by(post_type='2').filter_by(author=user)\
            .order_by(Post.date_posted.desc()).paginate(page=page, per_page=4)
    return render_template('user_post.html', posts = posts, user=user)

#Muestra todos los posts personales del ususario indicado
@users.route('/user/personal/<string:username>')
@login_required
def user_personal_post(username):
    user = User.query.filter_by(username=username).first_or_404()
    if user != current_user:
        current_app.logger.warning('[User: %s] [Message: Ha intentado acceder a los posts personales de %s]',current_user.username, user.username)
        abort(403)
    page = request.args.get('page', 1, type=int)
    posts = Post.query.filter_by(post_type='1').filter_by(author=user)\
            .order_by(Post.date_posted.desc()).paginate(page=page, per_page=4)
    return render_template('user_post.html', posts=posts, user=user)


#Para ver los posts publicos i privados de los usuarios que no eres tu
@users.route('/user/users/<string:username>')
@login_required
def user_users_post(username):
    user = User.query.filter_by(username=username).first_or_404()
    if user != current_user:
        current_app.logger.warning('[User: %s] [Message: Ha intenatado acceder a una funcionalidad no permitida %s]',current_user.username, user.username)
        return redirect(url_for('main.home'))
    page = request.args.get('page', 1, type=int)
    posts = Post.query.filter(Post.post_type!='1').filter(Post.user_id != user.id)\
            .order_by(Post.date_posted.desc()).paginate(page=page, per_page=4)
    return render_template('user_post.html', posts=posts, user=user)


#Muestra todos los posts privados del ususario indicado
@users.route('/user/private/<string:username>')
@login_required
def user_private_post(username):
    user = User.query.filter_by(username=username).first_or_404()
    page = request.args.get('page', 1, type=int)
    posts = Post.query.filter_by(post_type='0').filter_by(author=user)\
            .order_by(Post.date_posted.desc()).paginate(page=page, per_page=4)
    return render_template('user_post.html', posts = posts, user=user)


@users.route("/reset_password", methods=['GET', 'POST'])
def reset_request():
    if current_user.is_authenticated:
        flash('You are already logged in, no need to reset the password', 'info')
        return redirect(url_for('main.home'))
    resetForm = RequestResetForm()
    if resetForm.validate_on_submit():
        user = User.query.filter_by(username=resetForm.username.data).first()
        email = User.query.filter_by(email=resetForm.email.data).first()
        if user != email:
            current_app.logger.warning('[IP: %s] [Message: Ha intentado resetear la contraseña de un usuario y correo que no coinciden %s]', request.remote_addr)
            flash('That username does not belong to that email', 'danger')
            return redirect(url_for('main.home'))
        session['username'] = user.username
        current_app.logger.info('[IP: %s] [Message: EL usuario va a proceder a las preguntas para reseteo de contraseña %s]', request.remote_addr, user.username)
        flash('Answer correctly the personal cuestions or the authentication code for a reset email', 'info')
        return redirect(url_for('users.challenge'))
    return render_template('reset_request.html', title='Reset Password', form=resetForm)


@users.route("/challenge", methods=['GET', 'POST'])
def challenge():
    if 'username' not in session:
        current_app.logger.warning('[IP: %s] [Message: Ha intentado hacer las preguntas saltandose un paso previo  %s]', request.remote_addr)
        abort(403)
    user = User.query.filter_by(username=session['username']).first()
    if user is None:
        current_app.logger.warning('[IP: %s] [Message: Session de usuario no encontrada %s]', request.remote_addr)
        return redirect(url_for('main.home'))
    challengeForm = ChallengeForm()
    if challengeForm.validate_on_submit():
        if challengeForm.personalPosts.data and challengeForm.registrationMonth.data and challengeForm.registrationYear.data:
            if ((int(challengeForm.personalPosts.data ) == int(Post.query.filter_by(post_type='1').filter_by(author=user).count())) \
                and (user.registration_date.year == int(challengeForm.registrationYear.data)) \
                and (user.registration_date.month == int(challengeForm.registrationMonth.data))):
                    current_app.logger.info('[IP: %s] [Message: Ha respondido correctamente a las cuestiones personales del usuario %s]', request.remote_addr, user.username)
                    send_reset_email(user)
                    current_app.logger.info('[User: %s] [Message: Ha recibido el correo para cambiar su contraseña]', user.username)
                    del session['username']
                    flash('An email has been sent to reset your password.', 'info')
                    return redirect(url_for('users.login'))
        if challengeForm.token.data:
            if user.verify_totp(challengeForm.token.data):
                current_app.logger.info('[IP: %s] [Message: Ha introducido correctamente el token del usuario %s]', request.remote_addr, user.username)
                send_reset_email(user)
                current_app.logger.info('[User: %s] [Message: Ha recibido el correo para cambiar su contraseña]', user.username)
                del session['username']
                flash('An email has been sent to reset your password.', 'info')
                return redirect(url_for('users.login'))
        del session['username']
        flash('Worngs answers. The email will not be sent', 'danger')
        current_app.logger.warning('[User: %s] [Message: No ha completado las preguntas personales ni el token de seguridad]', user.username)
        return redirect(url_for('main.home'))
    return render_template('challenge.html', title='Challenge reset', form=challengeForm)


@users.route("/reset_password/<token>", methods=['GET', 'POST'])
def reset_token(token):
    if current_user.is_authenticated:
        flash('You are already logged in, no need to reset the password', 'info')
        return redirect(url_for('main.home'))
    user = User.verify_reset_token(token)
    if user is None:
        current_app.logger.warning('[IP: %s] [Message: Token caducado o incorrecto para el reseteo de contraseña %s]', request.remote_addr)
        flash('That is an invalid or expired token', 'danger')
        return redirect(url_for('users.reset_request'))
    passwordResetform = ResetPasswordForm()
    if passwordResetform.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(passwordResetform.password.data).decode('utf-8')
        user.password = hashed_password
        db.session.commit()
        current_app.logger.info('[User: %s] [Message: Ha actualizado su contraseña %s]', user.username)
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
        current_app.logger.warning('[IP: %s] [Message: Token caducado o incorrecto para la activación de la cuenta %s]', request.remote_addr)
        return redirect(url_for('users.login'))
    else:
        user.confirmed = True
        db.session.commit()
        current_app.logger.info('[User: %s] [Message: Ha activado su cuenta %s]', user.username)
        flash('Account activated. Now you can login into Social Medium', 'success')
        return redirect(url_for('users.login'))


@users.route("/user/<string:username>/delete", methods=['GET','POST'])
@login_required
def delete_user(username):
    user = User.query.filter_by(username=username).first_or_404()
    if user != current_user:
        current_app.logger.info('[User: %s] [Message: Ha intenado borrar la cuenta del usuario %s]', current_user.username, user.username)
        abort(403)
    #No hace falta tenemos on delete cascade
    #Post.query.filter_by(user_id=user.id).delete()
    current_app.logger.info('[User: %s] [Message: Ha borrado su cuenta %s]', user.username)
    logout_user()
    db.session.delete(user)
    db.session.commit()
    
    flash('User deleted!', 'success')
    return redirect(url_for('main.home'))


#QR
@users.route('/qrcode')
def qrcode():
    if 'username' not in session:
        current_app.logger.warning('[IP: %s] [Message: Ha intentado acceder directamente al qrcode %s]', request.remote_addr)
        abort(404)
    user = User.query.filter_by(username=session['username']).first()
    if user is None:
        current_app.logger.warning('[IP: %s] [Message: Usuario inexistente %s]', request.remote_addr)
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
        current_app.logger.warning('[IP: %s] [Message: Ha intentado acceder directamente al twofactor %s]', request.remote_addr)
        return redirect(url_for('main.home'))
    user = User.query.filter_by(username=session['username']).first()
    if user is None:
        current_app.logger.warning('[IP: %s] [Message: Usuario inexistente %s]', request.remote_addr)
        return redirect(url_for('main.home'))
    # since this page contains the sensitive qrcode, make sure the browser
    # does not cache it
    return render_template('two-factor-setup.html'), 200, {
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Pragma': 'no-cache',
        'Expires': '0'}
