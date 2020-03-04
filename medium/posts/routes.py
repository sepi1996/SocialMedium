from flask import (Blueprint, render_template, url_for, flash,
                   redirect, request, abort)
from flask_login import current_user, login_required
from medium import db
from medium.models import Post
from medium.posts.forms import PostForm


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

