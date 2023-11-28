import test_data


def test_register_success(remote_client):
    result = remote_client.register('user1', test_data.sig_alg, test_data.public_key, test_data.secret_key)
    assert result == True