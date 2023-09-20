import base64
import oqs
import helpers
import test_data

def test_login_success(client):
    # Login
    helpers.login(client, test_data.known_username, test_data.known_sig_alg, test_data.known_sig_key_secret)