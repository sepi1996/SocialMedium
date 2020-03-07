from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager
from flask_mail import Mail
from medium.config import Config
import logging
from logging.handlers import RotatingFileHandler

db = SQLAlchemy()
bcrypt = Bcrypt()
login_manager = LoginManager()
login_manager.login_view = 'users.login'
login_manager.login_message_category = 'primary'
mail = Mail()




def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(Config)


    formatter = logging.Formatter("[%(asctime)s] {%(pathname)s:%(lineno)d} %(levelname)s - %(message)s")
    #Cuando Medium.log ocupe 10Mb se creara un nuevo log, y el antiguo pasara a ser app.log.1 hasta un máximo de 10 en este caso
    handler = RotatingFileHandler('Medium.log', maxBytes=10000000, backupCount=10)
    logging.getLogger().setLevel(logging.INFO)
    handler.setFormatter(formatter)
    app.logger.addHandler(handler)


    db.init_app(app)
    bcrypt.init_app(app)
    login_manager.init_app(app)
    mail.init_app(app)

    from medium.users.routes import users
    from medium.posts.routes import posts
    from medium.main.routes import main
    from medium.errors.handlers import errors
    app.register_blueprint(users)
    app.register_blueprint(posts)
    app.register_blueprint(main)
    app.register_blueprint(errors)

    return app