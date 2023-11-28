import test_data

def test_send_message(remote_client_generator):
    client_1 = remote_client_generator()
    client_2 = remote_client_generator()
    
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
    
    assert client_1.get_contacts()
    assert client_2.get_contacts()
    
    assert client_1.send_message('user2', 'Hello, world!') == 'Message sent'
    
def test_list_messages(remote_client_generator):
    client_1 = remote_client_generator()
    client_2 = remote_client_generator()
    
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
    
    assert client_1.get_contacts()
    assert client_2.get_contacts()
    
    assert client_1.send_message('user2', 'Hello, world!') == 'Message sent'
    
    messages = client_2.get_messages('user1')
    
    assert len(messages) == 1
    assert messages[0]['incoming'] == True
    assert messages[0]['message'] == 'Hello, world!'