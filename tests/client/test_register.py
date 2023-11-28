import test_data


def test_register_success(remote_client):
    remote_client.gen_sig_key(test_data.sig_alg)
    remote_client.gen_kem_key(test_data.kem_alg)
    assert remote_client.register('user1')