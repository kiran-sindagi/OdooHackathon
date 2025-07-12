from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_migrate import Migrate
from flask_bcrypt import Bcrypt
from flask_ckeditor import CKEditor

# Initialize extensions
login_manager = LoginManager()
db = SQLAlchemy()
migrate = Migrate()
bcrypt = Bcrypt()
ckeditor = CKEditor()

def create_app():
    import os
    base_dir = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))
    app = Flask(__name__, template_folder=os.path.join(base_dir, 'templates'))
    app.config['SECRET_KEY'] = 'your-secret-key'
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///stackit.db'
    app.config['CKEDITOR_PKG_TYPE'] = 'full'
    app.config['CKEDITOR_FILE_UPLOADER'] = 'main.upload'

    db.init_app(app)
    migrate.init_app(app, db)
    login_manager.init_app(app)
    bcrypt.init_app(app)
    ckeditor.init_app(app)

    from .routes import main
    app.register_blueprint(main)

    return app
