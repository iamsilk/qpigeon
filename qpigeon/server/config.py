import secrets

class Config:
    SECRET_KEY = secrets.token_bytes(32)
    DEBUG = False
    SQLALCHEMY_DATABASE_URI = 'sqlite:///prod.db'

class DevelopmentConfig(Config):
    DEBUG = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///dev.db'

class TestingConfig(Config):
    DEBUG = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///testing.db'