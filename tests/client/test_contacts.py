import base64
import test_data


def test_get_contacts_empty(remote_client):
    remote_client.load_sig_key(test_data.known_sig_alg, test_data.known_sig_secret_key, test_data.known_sig_public_key)
    assert remote_client.login(test_data.known_username)
    
    contacts = remote_client.get_contacts()
    assert contacts == []


def test_add_contact(remote_client_generator):
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
    
    assert client_1.add_contact('user2') == 'Contact request sent'
    
    # should be able to add the same contact again
    assert client_1.add_contact('user2') == 'Contact request sent'


def test_get_contact_requests(remote_client_generator):
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
    
    contacts = client_1.get_contacts()
    assert contacts == []
    
    contact_requests = client_2.get_contact_requests()
    assert len(contact_requests) == 1
    
    contact_request = contact_requests[0]
    assert contact_request['username'] == 'user1'
    assert contact_request['sig_alg'] == client_1.sig_alg
    assert contact_request['sig_key'] == base64.b64encode(client_1.sig_public_key).decode()
    
    assert contact_request['signed_request']['action'] == '/api/contact/add'
    assert contact_request['signed_request']['username'] == 'user2'


def test_get_contacts(remote_client_generator):
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
    
    assert client_1.get_contacts() == []
    assert client_2.get_contacts() == []
    
    assert client_2.add_contact('user1')
    
    contacts = client_1.get_contacts()
    assert len(contacts) == 1
    assert contacts[0]['username'] == 'user2'
    assert contacts[0]['sig_alg'] == client_2.sig_alg
    assert contacts[0]['sig_key'] == base64.b64encode(client_2.sig_public_key).decode()
        
    contacts = client_2.get_contacts()
    assert len(contacts) == 1
    assert contacts[0]['username'] == 'user1'
    assert contacts[0]['sig_alg'] == client_1.sig_alg
    assert contacts[0]['sig_key'] == base64.b64encode(client_1.sig_public_key).decode()


def test_remove_contact(remote_client_generator):
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
    
    assert len(client_1.get_contacts()) == 1
    assert len(client_2.get_contacts()) == 1
    
    assert client_1.remove_contact('user2')
    
    assert len(client_1.get_contacts()) == 0
    assert len(client_2.get_contacts()) == 0


def test_reject_contact_request(remote_client_generator):
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
    
    assert client_1.add_contact('user2') == 'Contact request sent'
    assert client_2.remove_contact('user1') == 'Contact request rejected'


def test_cancel_contact_request(remote_client_generator):
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
    
    assert client_1.add_contact('user2') == 'Contact request sent'
    assert client_1.remove_contact('user2') == 'Contact request cancelled'
    
    # should be able to cancel the same contact request again
    assert client_1.remove_contact('user2') == 'Contact request cancelled'