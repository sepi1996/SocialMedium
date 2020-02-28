from flask import Blueprint, render_template, url_for, flash, redirect, request 
from flask_login import login_user, current_user, logout_user, login_required
from medium import db, bcrypt
from medium.models import User, Post
from medium.users.forms import (RegistrationForm, LoginForm, UpdateAccountForm,
                                   RequestResetForm, ResetPasswordForm)
from medium.users.utils import save_picture, send_reset_email

users = Blueprint('users', __name__)

@users.route("/register", methods=['GET', 'POST'])
def register():

    registerForm = RegistrationForm()
    if registerForm.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(registerForm.password.data).decode('utf-8')
        user = User(username = registerForm.username.data,
                    email = registerForm.email.data,
                    password = hashed_password)
        db.session.add(user)
        db.session.commit()
        flash(f'Your new account has been created!', 'success')
        return redirect(url_for('users.login'))
    return render_template('register.html', title='Register', form=registerForm)

@users.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main.home'))
    loginForm = LoginForm()
    if loginForm.validate_on_submit():
        user = User.query.filter_by(email=loginForm.email.data).first()
        if user and bcrypt.check_password_hash(user.password, loginForm.password.data):
            login_user(user, remember=loginForm.remember.data)
            next_page = request.args.get('next')
            if next_page:
                flash(f'Welcome to Social Medium {user.username}', 'success')
                return redirect(next_page)
            else:
                flash(f'Welcome to Social Medium {user.username}', 'success')
                return redirect(url_for('main.home'))
        else:
            flash('Login Unsuccessful. Please try again', 'warning')
    return render_template('login.html', title='Login', form=loginForm)

@users.route("/logout", methods=['GET'])
def logout():
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

@users.route('/user/<string:username>')
def user_post(username):
    page = request.args.get('page', 1, type=int)
    user = User.query.filter_by(username=username).first_or_404()
    posts = Post.query.filter_by(author=user)\
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