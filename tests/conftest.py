import pytest
from qpigeon.server import create_app
from qpigeon.server.config import TestingConfig
from qpigeon.server.models import db as _db
from test_data import setup_test_data

@pytest.fixture
def db():
    return _db

@pytest.fixture()
def app(db):
    app = create_app(TestingConfig)

    # reset database
    with app.app_context():
        db.drop_all()
        db.create_all()
        db.session.commit()

    with app.app_context():
        setup_test_data(db)

    yield app

@pytest.fixture()
def client(app):
    return app.test_client()

@pytest.fixture()
def runner(app):
    return app.test_cli_runner()

@pytest.fixture()
def remote_client(app):
    from qpigeon.client.client import Client
    return Client('http://localhost:5000/api')