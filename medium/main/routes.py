from flask import  Blueprint, render_template, request, redirect, url_for
from medium.models import Post
from flask_login import current_user
from medium.posts.forms import SearchForm
main = Blueprint('main', __name__)

@main.route('/', methods=['GET', 'POST'])
@main.route('/home', methods=['GET', 'POST'])
def home():
    searchForm = SearchForm()
    if searchForm.validate_on_submit():
        word = searchForm.post_word.data
        return redirect(url_for('posts.post_search', word=word))
    elif request.method == 'GET':
        page = request.args.get('page', 1, type=int)
        if current_user.is_authenticated:
            posts = Post.query.filter(Post.post_type!='1').order_by(Post.date_posted.desc()).paginate(page=page, per_page=7)
        else:
            posts = Post.query.filter_by(post_type='2').order_by(Post.date_posted.desc()).paginate(page=page, per_page=7)
        return render_template('home.html', posts=posts, form=searchForm)

