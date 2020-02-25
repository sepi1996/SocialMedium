from flask import render_template, url_for, flash, redirect, request
from medium.forms import RegistrationForm, LoginForm
from medium import app, db, bcrypt
from flask_login import login_user, current_user, logout_user, login_required
from medium.models import User, Post


posts = [
    {
        'author': 'Pepe Perez',
        'title': 'Title 1',
        'content': 'First Post',
        'date_posted': 'April 11, 2018'
    },
    {
        'author': 'Pepe Perez2',
        'title': 'Title 2',
        'content': 'Second Post',
        'date_posted': 'April 22, 2018'
    }
]

@app.route('/')
@app.route('/home')
def home():
    return render_template('home.html', posts=posts)


@app.route('/about')
def about():
    return render_template('about.html')

@app.route("/register", methods=['GET', 'POST'])
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
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=registerForm)

@app.route("/login", methods=['GET', 'POST'])
def login():
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
                return redirect(url_for('home'))
        else:
            flash('Login Unsuccessful. Please try again', 'warning')
    return render_template('login.html', title='Login', form=loginForm)

@app.route("/logout", methods=['GET'])
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route("/account", methods=['GET'])
@login_required
def account():
    
    return render_template('account.html', title='Account')