from flask import render_template, url_for, flash, redirect, request, abort
from medium.forms import RegistrationForm, UpdateAccountForm, LoginForm, PostForm
from medium import app, db, bcrypt
from flask_login import login_user, current_user, logout_user, login_required
from medium.models import User, Post
import secrets
import os
from PIL import Image

@app.route('/')
@app.route('/home')
def home():
    posts = Post.query.all()
    return render_template('home.html', posts = posts)


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

def save_picture(form_picture):
    randomHex = secrets.token_hex(8)
    _, fileExt = os.path.splitext(form_picture.filename)#El primero es _ porque no queremos almacenar ese valor devuleto por la funcion
    pictureFilename = randomHex + fileExt
    picturePath = os.path.join(app.root_path, 'static/profilePictures', pictureFilename)
    #Redimensionamos la imagem, para no almazenar imagenes grandes que ocupan mas, sin ser necesario
    size = (115, 115)
    newImage = Image.open(form_picture)
    newImage.thumbnail(size)
    newImage.save(picturePath)

    return pictureFilename

@app.route("/account", methods=['GET', 'POST'])
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
        return redirect(url_for('account'))#Haccemos un redirect para asi hacer una petición tipo GET y no POST
    elif request.method == 'GET':
        accountForm.username.data = current_user.username
        accountForm.email.data = current_user.email
    image_path = url_for('static', filename=f'profilePictures/{current_user.image_file}')
    return render_template('account.html', title='Account', image_path=image_path, form=accountForm)


@app.route("/post/new", methods=['GET', 'POST'])
@login_required
def new_post():
    postForm = PostForm()
    if postForm.validate_on_submit():
        post = Post(title = postForm.title.data,
                    content = postForm.content.data,
                    author = current_user)
        db.session.add(post)
        db.session.commit()
        flash(f'Your post {postForm.title.data} has been created', 'success')
        return redirect(url_for('home'))
    return render_template('create_post.html', title='New Post', legend='New Post', form=postForm)

@app.route("/post/<int:post_id>", methods=['GET'])
@login_required
def post(post_id):
    post = Post.query.get_or_404(post_id)
    return render_template('post.html', title=post.title, post=post)

@app.route("/post/<int:post_id>/update", methods=['GET', 'POST'])
@login_required
def update_post(post_id):
    post = Post.query.get_or_404(post_id)
    if post.author != current_user:
        abort(403)
    postForm = PostForm()
    if postForm.validate_on_submit():
        post.title = postForm.title.data
        post.content = postForm.content.data
        db.session.commit()#No necesitamos hacer un add ya que estamos trabajando sobre un post ya creado
        flash('Post updated!', 'success')
        return redirect(url_for('post', post_id=post.id))
    elif request.method == 'GET':
        postForm.title.data = post.title
        postForm.content.data = post.content
    
    return render_template('create_post.html', title='Update Post', legend='Update Post', form=postForm)


@app.route("/post/<int:post_id>/delete", methods=['POST'])
@login_required
def delete_post(post_id):
    post = Post.query.get_or_404(post_id)
    if post.author != current_user:
        abort(403)
    db.session.delete(post)
    db.session.commit()
    flash('Post deleted!', 'success')
    return redirect(url_for('home'))