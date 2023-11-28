import test_data


def test_login_success(remote_client):
    remote_client.load_sig_key(test_data.known_sig_alg, test_data.known_sig_secret_key, test_data.known_sig_public_key)
    assert remote_client.login(test_data.known_username)
    assert remote_client.username == test_data.known_username