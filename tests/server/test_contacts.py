import base64
import helpers
import test_data
from qpigeon.shared.crypto import verify_signature

def test_contact_request_send(client):
    sig_alg = test_data.known_sig_alg
    kem_alg = test_data.known_kem_alg

    # Register user 1
    username_1 = 'user1'
    sig_key_public_1, sig_key_secret_1 = helpers.generate_sig_keypair(sig_alg)
    kem_key_public_1, kem_key_secret_1 = helpers.generate_kem_keypair(kem_alg)
    kem_key_signature_1 = helpers.sign_kem(kem_key_public_1, sig_alg, sig_key_secret_1)
    
    helpers.register(client, username_1, sig_alg, sig_key_public_1, sig_key_secret_1,
                     test_data.known_kem_alg, kem_key_public_1, kem_key_secret_1, kem_key_signature_1)

    # Register user 2
    username_2 = 'user2'
    sig_key_public_2, sig_key_secret_2 = helpers.generate_sig_keypair(sig_alg)
    kem_key_public_2, kem_key_secret_2 = helpers.generate_kem_keypair(kem_alg)
    kem_key_signature_2 = helpers.sign_kem(kem_key_public_2, sig_alg, sig_key_secret_2)
        
    helpers.register(client, username_2, sig_alg, sig_key_public_2, sig_key_secret_2,
                     test_data.known_kem_alg, kem_key_public_2, kem_key_secret_2, kem_key_signature_2)
    
    # Login user 1
    helpers.login(client, username_1, sig_alg, sig_key_secret_1)

    # Send request to user 2
    helpers.contact_add(client, sig_alg, sig_key_secret_1, username_2)

    # Request sent again should work
    helpers.contact_add(client, sig_alg, sig_key_secret_1, username_2)

    # Login user 2
    helpers.login(client, username_2, sig_alg, sig_key_secret_2)

    # Get contact requests
    request_list = helpers.contact_request_list(client, sig_alg, sig_key_secret_2)
    assert len(request_list) == 1
    assert request_list[0]['username'] == username_1
    assert request_list[0]['sig_alg'] == sig_alg
    assert request_list[0]['sig_key'] == base64.b64encode(sig_key_public_1).decode()
    assert request_list[0]['kem_alg'] == kem_alg
    assert request_list[0]['kem_key'] == base64.b64encode(kem_key_public_1).decode()
    assert request_list[0]['kem_signature'] == base64.b64encode(kem_key_signature_1).decode()
    
    signed_request = request_list[0]['signed_request']
    assert signed_request is not None
    assert verify_signature(
        sig_alg,
        sig_key_public_1,
        base64.b64decode(signed_request['signature']),
        signed_request['timestamp'],
        base64.b64decode(signed_request['nonce']),
        signed_request['action'],
        signed_request['username']
    )

def test_contact_request_accept(client):
    sig_alg = test_data.known_sig_alg
    kem_alg = test_data.known_kem_alg

    # Register user 1
    username_1 = 'user1'
    sig_key_public_1, sig_key_secret_1 = helpers.generate_sig_keypair(sig_alg)
    kem_key_public_1, kem_key_secret_1 = helpers.generate_kem_keypair(kem_alg)
    kem_key_signature_1 = helpers.sign_kem(kem_key_public_1, sig_alg, sig_key_secret_1)
    
    helpers.register(client, username_1, sig_alg, sig_key_public_1, sig_key_secret_1,
                     test_data.known_kem_alg, kem_key_public_1, kem_key_secret_1, kem_key_signature_1)

    # Register user 2
    username_2 = 'user2'
    sig_key_public_2, sig_key_secret_2 = helpers.generate_sig_keypair(sig_alg)
    kem_key_public_2, kem_key_secret_2 = helpers.generate_kem_keypair(kem_alg)
    kem_key_signature_2 = helpers.sign_kem(kem_key_public_2, sig_alg, sig_key_secret_2)
        
    helpers.register(client, username_2, sig_alg, sig_key_public_2, sig_key_secret_2,
                     test_data.known_kem_alg, kem_key_public_2, kem_key_secret_2, kem_key_signature_2)
    
    # Login user 1
    helpers.login(client, username_1, sig_alg, sig_key_secret_1)

    # Send request to user 2
    helpers.contact_add(client, sig_alg, sig_key_secret_1, username_2)

    # Login user 2
    helpers.login(client, username_2, sig_alg, sig_key_secret_2)

    # Check contact requests before
    request_list = helpers.contact_request_list(client, sig_alg, sig_key_secret_2)
    assert len(request_list) == 1

    # Check contact list before
    contact_list = helpers.contact_list(client, sig_alg, sig_key_secret_2)
    assert len(contact_list) == 0

    # Accept contact request
    helpers.contact_add(client, sig_alg, sig_key_secret_2, username_1)

    # Check contact requests after
    request_list = helpers.contact_request_list(client, sig_alg, sig_key_secret_2)
    assert len(request_list) == 0

    # Check contact list after
    contact_list = helpers.contact_list(client, sig_alg, sig_key_secret_2)
    assert len(contact_list) == 1
    assert contact_list[0]['username'] == username_1
    assert contact_list[0]['sig_alg'] == sig_alg
    assert contact_list[0]['sig_key'] == base64.b64encode(sig_key_public_1).decode()
    assert contact_list[0]['kem_alg'] == kem_alg
    assert contact_list[0]['kem_key'] == base64.b64encode(kem_key_public_1).decode()
    assert contact_list[0]['kem_signature'] == base64.b64encode(kem_key_signature_1).decode()
    
    signed_accept = contact_list[0]['signed_accept']
    assert signed_accept is not None
    assert verify_signature(
        sig_alg,
        sig_key_public_1,
        base64.b64decode(signed_accept['signature']),
        signed_accept['timestamp'],
        base64.b64decode(signed_accept['nonce']),
        signed_accept['action'],
        signed_accept['username']
    )

    # Login user 1
    helpers.login(client, username_1, sig_alg, sig_key_secret_1)

    # Check contact list
    contact_list = helpers.contact_list(client, sig_alg, sig_key_secret_1)
    assert len(contact_list) == 1
    assert contact_list[0]['username'] == username_2
    assert contact_list[0]['sig_alg'] == sig_alg
    assert contact_list[0]['sig_key'] == base64.b64encode(sig_key_public_2).decode()
    assert contact_list[0]['kem_alg'] == kem_alg
    assert contact_list[0]['kem_key'] == base64.b64encode(kem_key_public_2).decode()
    assert contact_list[0]['kem_signature'] == base64.b64encode(kem_key_signature_2).decode()
    
    signed_accept = contact_list[0]['signed_accept']
    assert signed_accept is not None
    assert verify_signature(
        sig_alg,
        sig_key_public_2,
        base64.b64decode(signed_accept['signature']),
        signed_accept['timestamp'],
        base64.b64decode(signed_accept['nonce']),
        signed_accept['action'],
        signed_accept['username']
    )

def test_contact_request_reject(client):
    sig_alg = test_data.known_sig_alg
    kem_alg = test_data.known_kem_alg

    # Register user 1
    username_1 = 'user1'
    sig_key_public_1, sig_key_secret_1 = helpers.generate_sig_keypair(sig_alg)
    kem_key_public_1, kem_key_secret_1 = helpers.generate_kem_keypair(kem_alg)
    kem_key_signature_1 = helpers.sign_kem(kem_key_public_1, sig_alg, sig_key_secret_1)
    
    helpers.register(client, username_1, sig_alg, sig_key_public_1, sig_key_secret_1,
                     test_data.known_kem_alg, kem_key_public_1, kem_key_secret_1, kem_key_signature_1)

    # Register user 2
    username_2 = 'user2'
    sig_key_public_2, sig_key_secret_2 = helpers.generate_sig_keypair(sig_alg)
    kem_key_public_2, kem_key_secret_2 = helpers.generate_kem_keypair(kem_alg)
    kem_key_signature_2 = helpers.sign_kem(kem_key_public_2, sig_alg, sig_key_secret_2)
        
    helpers.register(client, username_2, sig_alg, sig_key_public_2, sig_key_secret_2,
                     test_data.known_kem_alg, kem_key_public_2, kem_key_secret_2, kem_key_signature_2)
    
    # Login user 1
    helpers.login(client, username_1, sig_alg, sig_key_secret_1)

    # Send request to user 2
    helpers.contact_add(client, sig_alg, sig_key_secret_1, username_2)

    # Login user 2
    helpers.login(client, username_2, sig_alg, sig_key_secret_2)

    # Check contact requests before
    request_list = helpers.contact_request_list(client, sig_alg, sig_key_secret_2)
    assert len(request_list) == 1

    # Check contact list before
    contact_list = helpers.contact_list(client, sig_alg, sig_key_secret_2)
    assert len(contact_list) == 0

    # Reject contact request
    helpers.contact_remove(client, sig_alg, sig_key_secret_2, username_1)

    # Check contact requests after
    request_list = helpers.contact_request_list(client, sig_alg, sig_key_secret_2)
    assert len(request_list) == 0

    # Check contact list after
    contact_list = helpers.contact_list(client, sig_alg, sig_key_secret_2)
    assert len(contact_list) == 0

def test_contact_remove(client):
    sig_alg = test_data.known_sig_alg
    kem_alg = test_data.known_kem_alg

    # Register user 1
    username_1 = 'user1'
    sig_key_public_1, sig_key_secret_1 = helpers.generate_sig_keypair(sig_alg)
    kem_key_public_1, kem_key_secret_1 = helpers.generate_kem_keypair(kem_alg)
    kem_key_signature_1 = helpers.sign_kem(kem_key_public_1, sig_alg, sig_key_secret_1)
    
    helpers.register(client, username_1, sig_alg, sig_key_public_1, sig_key_secret_1,
                     test_data.known_kem_alg, kem_key_public_1, kem_key_secret_1, kem_key_signature_1)

    # Register user 2
    username_2 = 'user2'
    sig_key_public_2, sig_key_secret_2 = helpers.generate_sig_keypair(sig_alg)
    kem_key_public_2, kem_key_secret_2 = helpers.generate_kem_keypair(kem_alg)
    kem_key_signature_2 = helpers.sign_kem(kem_key_public_2, sig_alg, sig_key_secret_2)
        
    helpers.register(client, username_2, sig_alg, sig_key_public_2, sig_key_secret_2,
                     test_data.known_kem_alg, kem_key_public_2, kem_key_secret_2, kem_key_signature_2)
    
    # Login user 1
    helpers.login(client, username_1, sig_alg, sig_key_secret_1)

    # Send request to user 2
    helpers.contact_add(client, sig_alg, sig_key_secret_1, username_2)

    # Login user 2
    helpers.login(client, username_2, sig_alg, sig_key_secret_2)

    # Accept contact request
    helpers.contact_add(client, sig_alg, sig_key_secret_2, username_1)

    # Check contact list
    contact_list = helpers.contact_list(client, sig_alg, sig_key_secret_2)
    assert len(contact_list) == 1
    
    # Remove contact
    helpers.contact_remove(client, sig_alg, sig_key_secret_2, username_1)

    # Check contact list
    contact_list = helpers.contact_list(client, sig_alg, sig_key_secret_2)
    assert len(contact_list) == 0

    # Login user 1
    helpers.login(client, username_1, sig_alg, sig_key_secret_1)

    # Check contact list
    contact_list = helpers.contact_list(client, sig_alg, sig_key_secret_1)
    assert len(contact_list) == 0