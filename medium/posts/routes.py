from flask import (Blueprint, render_template, url_for, flash,
                   redirect, request, abort)
from flask_login import current_user, login_required
from medium import db
from medium.models import Post
from medium.posts.forms import PostForm
from flask import current_app


posts = Blueprint('posts', __name__)


@posts.route("/post/new", methods=['GET', 'POST'])
@login_required
def new_post():
    postForm = PostForm()
    if postForm.validate_on_submit():
        post = Post(title = postForm.title.data,
                    content = postForm.content.data,
                    author = current_user,
                    public = postForm.public.data)
        db.session.add(post)
        db.session.commit()
        flash(f'Your post {postForm.title.data} has been created', 'success')
        return redirect(url_for('main.home'))
    return render_template('create_post.html', title='New Post', legend='New Post', form=postForm)

@posts.route("/post/<int:post_id>", methods=['GET'])
@login_required
def post(post_id):
    post = Post.query.get_or_404(post_id)
    return render_template('post.html', title=post.title, post=post)

@posts.route("/post/<int:post_id>/update", methods=['GET', 'POST'])
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
        return redirect(url_for('posts.post', post_id=post.id))
    elif request.method == 'GET':
        postForm.title.data = post.title
        postForm.content.data = post.content
    
    return render_template('create_post.html', title='Update Post', legend='Update Post', form=postForm)


@posts.route("/post/<int:post_id>/delete", methods=['POST'])
@login_required
def delete_post(post_id):
    post = Post.query.get_or_404(post_id)
    if post.author != current_user:
        abort(403)
    db.session.delete(post)
    db.session.commit()
    flash('Post deleted!', 'success')
    return redirect(url_for('main.home'))


@posts.route("/post/<int:post_id>/share", methods=['GET', 'POST'])
def share_post(post_id):
    post = Post.query.get_or_404(post_id)
    if post.author != current_user:
        abort(403)
    token = post.get_shared_token()
    post.shared_token = token
    db.session.commit()#No necesitamos hacer un add ya que estamos trabajando sobre un post ya creado
    flash('Shared link created!', 'success')
    return redirect(url_for('posts.post', post_id=post.id))


@posts.route("/post/<int:post_id>/disallow", methods=['GET', 'POST'])
def disallow_post(post_id):
    post = Post.query.get_or_404(post_id)
    if post.author != current_user:
        abort(403)
    if post.shared_token:
        post.shared_token = None
        db.session.commit()#No necesitamos hacer un add ya que estamos trabajando sobre un post ya creado
        flash('Shared link removed!', 'success')
    else:
        flash('This post was not shared', 'info')
    return redirect(url_for('posts.post', post_id=post.id))


@posts.route("/post/<token>", methods=['GET', 'POST'])
def token_share_post(token):
    if current_user.is_authenticated:
        flash('You are already logged in, no need to use this link to see the post', 'info')
        return redirect(url_for('main.home'))
    post = Post.verify_shared_token(token)
    current_app.logger.info('Post %s ', post)
    if post is None or post.shared_token is None: #IMPORTANTE el "post.shared_token is None", para que un usuario no se pude guardar el enlace de compartr y verlo cuando quiera
        flash('That is an invalid or expired token', 'danger')
        return redirect(url_for('users.login'))
    else:
        flash('Post shown thanks to a shared link', 'info')
        return render_template('post.html', title=post.title, post=post)
