from flask import render_template, url_for, flash, redirect
from medium.forms import RegistrationForm, LoginForm
from medium import app
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
        flash(f'Account created for {registerForm.username.data}!', 'success')
        return redirect(url_for('home'))
    return render_template('register.html', title='Register', form=registerForm)

@app.route("/login", methods=['GET', 'POST'])
def login():
    loginForm = LoginForm()
    if loginForm.validate_on_submit():
        if loginForm.email.data == 'admin@blog.com' and loginForm.password.data == 'password':
            flash('You have been logged in!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Login Unsuccessful. Please check username and password', 'warning')
    return render_template('login.html', title='Login', form=loginForm)
