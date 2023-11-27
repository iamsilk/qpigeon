import secrets

class Config:
    SECRET_KEY = secrets.token_bytes(32)
    DEBUG = False
    # Database should be set by environment variable in prod
    #SQLALCHEMY_DATABASE_URI = 'sqlite:///prod.db'
    TIME_THRESHOLD = 5 #seconds until timeout

class DevelopmentConfig(Config):
    DEBUG = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///dev.db'

class TestingConfig(Config):
    DEBUG = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///testing.db'