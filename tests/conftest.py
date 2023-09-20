import pytest
from qpigeon.server import create_app
from qpigeon.server.config import TestingConfig
from qpigeon.server.models import db as _db
from test_data import setup_test_data

@pytest.fixture()
def app():
    app = create_app(TestingConfig)

    # reset database
    with app.app_context():
        _db.drop_all()
        _db.create_all()

        setup_test_data(_db)

    yield app

@pytest.fixture
def db():
    return _db

@pytest.fixture()
def client(app):
    return app.test_client()

@pytest.fixture()
def runner(app):
    return app.test_cli_runner()