import pytest
from qpigeon.server import create_app
from qpigeon.server.config import TestingConfig
from qpigeon.server.models import db as _db
from test_data import setup_test_data

import requests_mock
from requests_mock_flask import add_flask_app_to_mock

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
def remote_client(app, client):
    from qpigeon.client.client import Client
    
    remote_client = Client('http://localhost.local/api')
    adapter = requests_mock.Adapter()
    remote_client.session.mount('http://', adapter)
    
    add_flask_app_to_mock(adapter, app, 'http://localhost.local')
    
    # cookies are not set by responses
    # the issue is described here https://github.com/jamielennox/requests-mock/issues/17
    # this is a hacky workaround
    def no_cookie_workaround(r, *args, **kwargs):
        remote_client.session.cookies.update(r.cookies)
        return r
    
    remote_client.session.hooks['response'].append(no_cookie_workaround)
    
    return remote_client