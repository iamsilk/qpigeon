import test_data


def test_register_success(remote_client):
    remote_client.gen_sig_key(test_data.sig_alg)
    assert remote_client.register('user1')