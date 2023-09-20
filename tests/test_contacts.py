import base64
import helpers
import test_data

def test_contact_request_send(client):
    sig_alg = test_data.known_sig_alg

    # Register user 1
    username_1 = 'user1'
    sig_key_public_1, sig_key_secret_1 = helpers.generate_keypair(sig_alg)
    helpers.register(client, username_1, sig_alg, sig_key_public_1, sig_key_secret_1)

    # Register user 2
    username_2 = 'user2'
    sig_key_public_2, sig_key_secret_2 = helpers.generate_keypair(sig_alg)
    helpers.register(client, username_2, sig_alg, sig_key_public_2, sig_key_secret_2)
    
    # Login user 1
    helpers.login(client, username_1, sig_alg, sig_key_secret_1)

    # Send request to user 2
    helpers.contact_request_send(client, username_2)

    # Request sent against should work
    helpers.contact_request_send(client, username_2)

    # Login user 2
    helpers.login(client, username_2, sig_alg, sig_key_secret_2)

    # Get contact requests
    request_list = helpers.contact_request_list(client)
    assert len(request_list) == 1
    assert request_list[0]['username'] == username_1
    assert request_list[0]['sig_alg'] == sig_alg
    assert request_list[0]['sig_key'] == base64.b64encode(sig_key_public_1).decode()

def test_contact_request_accept(client):
    sig_alg = test_data.known_sig_alg

    # Register user 1
    username_1 = 'user1'
    sig_key_public_1, sig_key_secret_1 = helpers.generate_keypair(sig_alg)
    helpers.register(client, username_1, sig_alg, sig_key_public_1, sig_key_secret_1)

    # Register user 2
    username_2 = 'user2'
    sig_key_public_2, sig_key_secret_2 = helpers.generate_keypair(sig_alg)
    helpers.register(client, username_2, sig_alg, sig_key_public_2, sig_key_secret_2)
    
    # Login user 1
    helpers.login(client, username_1, sig_alg, sig_key_secret_1)

    # Send request to user 2
    helpers.contact_request_send(client, username_2)

    # Login user 2
    helpers.login(client, username_2, sig_alg, sig_key_secret_2)

    # Check contact requests before
    request_list = helpers.contact_request_list(client)
    assert len(request_list) == 1

    # Check contact list before
    contact_list = helpers.contact_list(client)
    assert len(contact_list) == 0

    # Accept contact request
    helpers.contact_request_accept(client, username_1)

    # Check contact requests after
    request_list = helpers.contact_request_list(client)
    assert len(request_list) == 0

    # Check contact list after
    contact_list = helpers.contact_list(client)
    assert len(contact_list) == 1
    assert contact_list[0]['username'] == username_1
    assert contact_list[0]['sig_alg'] == sig_alg
    assert contact_list[0]['sig_key'] == base64.b64encode(sig_key_public_1).decode()

    # Login user 1
    helpers.login(client, username_1, sig_alg, sig_key_secret_1)

    # Check contact list
    contact_list = helpers.contact_list(client)
    assert len(contact_list) == 1
    assert contact_list[0]['username'] == username_2
    assert contact_list[0]['sig_alg'] == sig_alg
    assert contact_list[0]['sig_key'] == base64.b64encode(sig_key_public_2).decode()

def test_contact_request_reject(client):
    sig_alg = test_data.known_sig_alg

    # Register user 1
    username_1 = 'user1'
    sig_key_public_1, sig_key_secret_1 = helpers.generate_keypair(sig_alg)
    helpers.register(client, username_1, sig_alg, sig_key_public_1, sig_key_secret_1)

    # Register user 2
    username_2 = 'user2'
    sig_key_public_2, sig_key_secret_2 = helpers.generate_keypair(sig_alg)
    helpers.register(client, username_2, sig_alg, sig_key_public_2, sig_key_secret_2)
    
    # Login user 1
    helpers.login(client, username_1, sig_alg, sig_key_secret_1)

    # Send request to user 2
    helpers.contact_request_send(client, username_2)

    # Login user 2
    helpers.login(client, username_2, sig_alg, sig_key_secret_2)

    # Check contact requests before
    request_list = helpers.contact_request_list(client)
    assert len(request_list) == 1

    # Check contact list before
    contact_list = helpers.contact_list(client)
    assert len(contact_list) == 0

    # Reject contact request
    helpers.contact_request_reject(client, username_1)

    # Check contact requests after
    request_list = helpers.contact_request_list(client)
    assert len(request_list) == 0

    # Check contact list after
    contact_list = helpers.contact_list(client)
    assert len(contact_list) == 0

def test_contact_remove(client):
    sig_alg = test_data.known_sig_alg

    # Register user 1
    username_1 = 'user1'
    sig_key_public_1, sig_key_secret_1 = helpers.generate_keypair(sig_alg)
    helpers.register(client, username_1, sig_alg, sig_key_public_1, sig_key_secret_1)

    # Register user 2
    username_2 = 'user2'
    sig_key_public_2, sig_key_secret_2 = helpers.generate_keypair(sig_alg)
    helpers.register(client, username_2, sig_alg, sig_key_public_2, sig_key_secret_2)
    
    # Login user 1
    helpers.login(client, username_1, sig_alg, sig_key_secret_1)

    # Send request to user 2
    helpers.contact_request_send(client, username_2)

    # Login user 2
    helpers.login(client, username_2, sig_alg, sig_key_secret_2)

    # Accept contact request
    helpers.contact_request_accept(client, username_1)

    # Check contact list
    contact_list = helpers.contact_list(client)
    assert len(contact_list) == 1
    
    # Remove contact
    helpers.contact_remove(client, username_1)

    # Check contact list
    contact_list = helpers.contact_list(client)
    assert len(contact_list) == 0

    # Login user 1
    helpers.login(client, username_1, sig_alg, sig_key_secret_1)

    # Check contact list
    contact_list = helpers.contact_list(client)
    assert len(contact_list) == 0