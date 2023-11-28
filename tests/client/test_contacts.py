import test_data


def test_get_contacts(remote_client):
    remote_client.login(test_data.known_username, test_data.known_sig_alg, test_data.known_secret_key)
    
    contacts = remote_client.get_contacts()