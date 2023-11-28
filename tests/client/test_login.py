import test_data


def test_login_success(remote_client):
    result = remote_client.login(test_data.known_username, test_data.known_sig_alg, test_data.known_secret_key)
    assert result == True