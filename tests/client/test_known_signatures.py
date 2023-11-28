import base64
import test_data


def test_known_signatures(remote_client_generator):
    client_1 = remote_client_generator()
    client_2 = remote_client_generator()
    
    assert client_1.known_signatures == {}
    
    client_1.gen_sig_key(test_data.sig_alg)
    client_1.gen_kem_key(test_data.kem_alg)
    client_2.gen_sig_key(test_data.sig_alg)
    client_2.gen_kem_key(test_data.kem_alg)
    
    assert client_1.register('user1')
    assert client_2.register('user2')
    
    assert client_1.login('user1')
    assert client_2.login('user2')
    
    assert client_1.add_contact('user2')
    assert client_2.add_contact('user1')
    
    assert len(client_1.get_contacts()) == 1
    
    assert client_1.known_signatures == {
        'user2': {
            'sig_alg': test_data.sig_alg,
            'sig_public_key': base64.b64encode(client_2.sig_public_key).decode()
        }
    }