from flask import (Blueprint, render_template, url_for, flash,
                   redirect, request, abort)
from flask_login import current_user, login_required
from medium import db
from medium.models import Post
from medium.posts.forms import PostForm, SearchForm
from flask import current_app, session
from .forms import POST_TYPE
from Crypto import Random
from Crypto.Cipher.AES import block_size, key_size

from medium.posts.utils import create_personal_post, decrypt_personal_post, update_personal_post

posts = Blueprint('posts', __name__)

#Para crear posts
@posts.route("/post/new", methods=['GET', 'POST'])
@login_required
def new_post():
    postForm = PostForm()
    if postForm.validate_on_submit():
        if postForm.post_type.data == 1:
            if 'Pk' not in session:
                current_app.logger.warning('[User: %s] [Message: No ha podido crear post personal, no esta la llave en la sesion]',current_user.username)
                abort(404)
            else:
                post = create_personal_post(session['Pk'], current_user, postForm)
        else:
            post = Post(title = postForm.title.data,
                        content = postForm.content.data,
                        post_type = postForm.post_type.data,
                        author = current_user)
        db.session.add(post)
        db.session.commit()
        current_app.logger.info('[User: %s] [Message: Ha creado un nuevo post]',current_user.username)
        flash(f'Your post {postForm.title.data} has been created', 'success')      
        return redirect(url_for('main.home'))
    return render_template('create_post.html', title='New Post', legend='New Post', form=postForm)

#Para mostrar un post en concreto
@posts.route("/post/<int:post_id>", methods=['GET'])
def post(post_id):
    post = Post.query.get_or_404(post_id)
    if current_user.is_authenticated:
        if post.author != current_user and post.post_type=='1':
            current_app.logger.warning('[User: %s] [Message: Ha intenatado ver el post personal %d que no es suyo]',current_user.username, post.id)
            abort(403)
        elif post.author == current_user and post.post_type=='1':
            if 'Pk' not in session:
                current_app.logger.warning('[User: %s] [Message: No ha podido crear post personal, no esta la llave en la sesion]',current_user.username)
                abort(404)
            decrypt_personal_post(session['Pk'], current_user, post)
            return render_template('post.html', title=post.title, post=post)
        else:
            return render_template('post.html', title=post.title, post=post)
    else:
        if post.post_type == '2':
            return render_template('post.html', title=post.title, post=post)
        else:
            flash(f'You must login in to see that post', 'info') 
            return redirect(url_for('users.login'))

    

#Para actualizar un post
@posts.route("/post/<int:post_id>/update", methods=['GET', 'POST'])
@login_required
def update_post(post_id):
    post = Post.query.get_or_404(post_id)
    if post.author != current_user:
        current_app.logger.warning('[User: %s] [Message: Ha intenatado modificar el post %d que no es suyo]',current_user.username, post.id)
        abort(403)
    postForm = PostForm()
    if postForm.validate_on_submit():
        if postForm.post_type.data == 1:
            if 'Pk' not in session:
                current_app.logger.warning('[User: %s] [Message: No ha podido crear post personal, no esta la llave en la sesion]',current_user.username)
                abort(404)
            update_personal_post(session['Pk'], current_user, post, postForm)
        else:
            post.title = postForm.title.data
            post.content = postForm.content.data
            post.post_type = postForm.post_type.data
            post.iv_post = None
        db.session.commit()#No necesitamos hacer un add ya que estamos trabajando sobre un post ya creado
        current_app.logger.warning('[User: %s] [Message: Ha modficado el post %d]',current_user.username, post.id)
        flash('Post updated!', 'success')
        return redirect(url_for('posts.post', post_id=post.id))
    elif request.method == 'GET':
        if 'Pk' not in session:
            current_app.logger.warning('[User: %s] [Message: No ha podido crear post personal, no esta la llave en la sesion]',current_user.username)
            abort(404)
        if post.post_type == '1':
            decrypt_personal_post(session['Pk'], current_user, post)
        postForm.title.data = post.title
        postForm.content.data = post.content
        postForm.post_type.data = postForm.post_type.data
    
    return render_template('create_post.html', title='Update Post', legend='Update Post', form=postForm)


@posts.route('/post/search/<string:word>', methods=['GET', 'POST'])
def post_search(word):
    page = request.args.get('page', 1, type=int)
    search = "%{}%".format(word)
    if current_user.is_authenticated:
        posts = Post.query.filter(Post.post_type!='1').filter(Post.title.like(search))\
        .order_by(Post.date_posted.desc()).paginate(page=page, per_page=4)
    else:
        posts = Post.query.filter_by(post_type='2').filter(Post.title.like(search))\
        .order_by(Post.date_posted.desc()).paginate(page=page, per_page=4)
    return render_template('search_post.html', posts=posts, word=word) 

#Para que un usuario pueda eliminar un post
@posts.route("/post/<int:post_id>/delete", methods=['POST'])
@login_required
def delete_post(post_id):
    post = Post.query.get_or_404(post_id)
    if post.author != current_user:
        current_app.logger.warning('[User: %s] [Message: Ha intenatado eliminar el post %d que no es suyo]',current_user.username, post.id)
        abort(403)
    db.session.delete(post)
    db.session.commit()
    current_app.logger.info('[User: %s] [Message: Ha eliminado el post %d]',current_user.username, post.id)
    flash('Post deleted!', 'success')
    return redirect(url_for('main.home'))

#Para que un usuario pueda crear un enlace para compartir un post
@posts.route("/post/<int:post_id>/share", methods=['GET', 'POST'])
@login_required
def share_post(post_id):
    post = Post.query.get_or_404(post_id)
    if post.author != current_user or post.post_type == "1":
        current_app.logger.warning('[User: %s] [Message: Ha intenatado compartir el post sin que esto se pueda hacer %d ]',current_user.username, post.id)
        abort(403)
    token = post.get_shared_token()
    post.shared_token = token
    db.session.commit()#No necesitamos hacer un add ya que estamos trabajando sobre un post ya creado
    current_app.logger.info('[User: %s] [Message: Ha creado enlace para compartir el post %d]', current_user.username, post.id)
    flash('Shared link created!', 'success')
    return redirect(url_for('posts.post', post_id=post.id))


#Para que un usuario pueda eliminar un enlace para compartir un post
@posts.route("/post/<int:post_id>/disallow", methods=['GET', 'POST'])
def disallow_post(post_id):
    post = Post.query.get_or_404(post_id)
    if post.author != current_user:
        current_app.logger.info('[User: %s] [Message: Ha intenatado eliminar el enlace para compartir el post %d que no es suyo]',current_user.username, post.id)
        abort(403)
    if post.shared_token:
        post.shared_token = None
        db.session.commit()#No necesitamos hacer un add ya que estamos trabajando sobre un post ya creado
        current_app.logger.info('[User: %s] [Message: Ha eliminado el enlace para compartir el post %d]', current_user.username, post.id)
        flash('Shared link removed!', 'success')
    else:
        flash('This post was not shared', 'info')
    return redirect(url_for('posts.post', post_id=post.id))

#Para ver un post mediante un token
@posts.route("/post/<token>", methods=['GET', 'POST'])
def token_share_post(token):
    '''
    if current_user.is_authenticated:
        flash('You are already logged in, no need to use this link to see the post', 'info')
        return redirect(url_for('main.home'))
    '''
    post = Post.verify_shared_token(token)
    if post is None or post.shared_token is None: #IMPORTANTE el "post.shared_token is None", para que un usuario no se pude guardar el enlace de compartr y verlo cuando quiera
        flash('That is an invalid or expired token', 'danger')
        current_app.logger.warning('[Ip: %s] [Message: Ha intentado ver un post mediante un token invalido]', request.user_agent)
        return redirect(url_for('users.login'))
    else:
        flash('Post shown thanks to a shared link', 'info')
        return render_template('post.html', title=post.title, post=post)
