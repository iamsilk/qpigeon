import base64
import oqs
import secrets

class Config:
    SECRET_KEY = secrets.token_bytes(32)
    DEBUG = False
    # Database should be set by environment variable in prod
    #SQLALCHEMY_DATABASE_URI = 'sqlite:///prod.db'
    TIME_THRESHOLD = 60 # 60 seconds until timeout
    SESSION_TYPE = 'filesystem' # TODO: use redis in prod
    
    # TODO: use environment variables in prod
    SERVER_KEM_ALG = 'Kyber512'
    with oqs.KeyEncapsulation(SERVER_KEM_ALG) as kem:
        SERVER_KEM_PUBLIC_KEY = kem.generate_keypair()
        SERVER_KEM_SECRET_KEY = kem.export_secret_key()
    
    SERVER_SIG_ALG = 'Dilithium2'
    with oqs.Signature(SERVER_SIG_ALG) as signer:
        SERVER_SIG_PUBLIC_KEY = signer.generate_keypair()
        SERVER_SIG_SECRET_KEY = signer.export_secret_key()
        
        SERVER_KEM_SIGNATURE = signer.sign(SERVER_KEM_PUBLIC_KEY)
    
    SERVER_KEM_PUBLIC_KEY = base64.b64encode(SERVER_KEM_PUBLIC_KEY).decode()
    SERVER_SIG_PUBLIC_KEY = base64.b64encode(SERVER_SIG_PUBLIC_KEY).decode()
    SERVER_KEM_SIGNATURE = base64.b64encode(SERVER_KEM_SIGNATURE).decode()
    

class DevelopmentConfig(Config):
    DEBUG = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///dev.db'

class TestingConfig(Config):
    DEBUG = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///testing.db'