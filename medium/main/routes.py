from flask import  Blueprint, render_template, request
from medium.models import Post
from flask_login import current_user
main = Blueprint('main', __name__)

@main.route('/')
@main.route('/home')
def home():
    if current_user.is_authenticated:
        page = request.args.get('page', 1, type=int)
        posts = Post.query.order_by(Post.date_posted.desc()).paginate(page=page, per_page=7)
    else:
        page = request.args.get('page', 1, type=int)
        posts = Post.query.filter_by(public=True).order_by(Post.date_posted.desc()).paginate(page=page, per_page=7)
    return render_template('home.html', posts = posts)

