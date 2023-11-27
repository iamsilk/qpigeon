from flask import Flask
from .models import db
from .routes import api
from .config import Config
import secrets
import os

def create_app(config_class=Config):
    # Init app
    app = Flask(__name__)

    # Load config
    app.config.update({
        'SQLALCHEMY_DATABASE_URI': os.environ.get('DATABASE_URL'),
    })

    app.config.from_object(config_class)

    # Setup database
    db.init_app(app)

    with app.app_context():
        db.create_all()

    # Setup routes
    app.register_blueprint(api, url_prefix='/api')

    return app