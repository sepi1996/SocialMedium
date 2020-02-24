from flask import Flask
from flask_sqlalchemy import SQLAlchemy


 
app = Flask(__name__)
app.config['SECRET_KEY'] = '87n89frn89uy238907329879q'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///medium.db'
db = SQLAlchemy(app)

from medium import routes