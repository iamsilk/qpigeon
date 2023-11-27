import oqs
import test_data

def test_client_register_success(remote_client):
    result = remote_client.register('user1', test_data.sig_alg, test_data.public_key, test_data.secret_key)
    assert result == True


def test_client_login_success(remote_client):
    result = remote_client.login(test_data.known_username, test_data.known_sig_alg, test_data.known_secret_key)
    assert result == True