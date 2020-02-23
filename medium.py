from flask import Flask, render_template, url_for
from forms import RegistrationForm, LoginForm

app = Flask(__name__)

app.config['SECRET_KEY'] = '87n89frn89uy238907329879q'

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
    return render_template('register.html', title='Register', form=registerForm)

@app.route("/login", methods=['GET', 'POST'])
def login():
    loginForm = LoginForm()
    return render_template('login.html', title='Login', form=loginForm)


if __name__ == "__main__":
    app.run(debug=True)