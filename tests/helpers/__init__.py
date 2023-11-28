import oqs
import base64
import os
import datetime
from qpigeon.shared.crypto import generate_signature, decap_key

def generate_sig_keypair(sig_alg):
    with oqs.Signature(sig_alg) as signer:
        sig_key_public = signer.generate_keypair()
        sig_key_secret = signer.export_secret_key()

    return sig_key_public, sig_key_secret

def generate_kem_keypair(kem_alg):
    with oqs.KeyEncapsulation(kem_alg) as kem:
        kem_key_public = kem.generate_keypair()
        kem_key_secret = kem.export_secret_key()

    return kem_key_public, kem_key_secret

def sign_kem(kem_key_public, sig_alg, sig_key_secret):
    with oqs.Signature(sig_alg, sig_key_secret) as signer:
        return signer.sign(kem_key_public)

def get_timestamp_and_nonce():
    timestamp = int(datetime.datetime.now(datetime.UTC).timestamp())
    nonce = os.urandom(16)
    return timestamp, nonce

def sign_data_with_timestamp_and_nonce(sig_alg, sig_key_secret, *args):
    timestamp, nonce = get_timestamp_and_nonce()
    signature = generate_signature(sig_alg, sig_key_secret, timestamp, nonce, *args)
    return timestamp, nonce, signature

def try_register_challenge(client, username, sig_alg, sig_key_public, kem_alg, kem_key_public, kem_signature):
    return try_register_challenge_raw(
        client, username,
        sig_alg, base64.b64encode(sig_key_public).decode(),
        kem_alg, base64.b64encode(kem_key_public).decode(),
        base64.b64encode(kem_signature).decode()
    )

def try_register_challenge_raw(client, username, sig_alg, sig_key_public, kem_alg, kem_key_public, kem_signature):
    data = {}
    if username:
        data['username'] = username
    if sig_alg:
        data['sig_alg'] = sig_alg
    if sig_key_public:
        data['sig_key'] = sig_key_public
    if kem_alg:
        data['kem_alg'] = kem_alg
    if kem_key_public:
        data['kem_key'] = kem_key_public
    if kem_signature:
        data['kem_signature'] = kem_signature

    return client.post('/api/register/challenge', json=data)

def try_register_submit(client, challenge_signed, kem_challenge_secret):
    data = {}
    if challenge_signed:
        data['challenge_signed'] = base64.b64encode(challenge_signed).decode()
    if kem_challenge_secret:
        data['kem_challenge_secret'] = base64.b64encode(kem_challenge_secret).decode()

    return client.post('/api/register/submit', json=data)

def register(client, username, sig_alg, sig_key_public, sig_key_secret, kem_alg, kem_key_public, kem_key_secret, kem_signature):
    # Request challenge

    response = try_register_challenge(client, username, sig_alg, sig_key_public, kem_alg, kem_key_public, kem_signature)

    assert response.status_code == 200
    assert 'sig_challenge' in response.json
    assert 'kem_challenge' in response.json

    sig_challenge = base64.b64decode(response.json['sig_challenge'])
    kem_challenge = base64.b64decode(response.json['kem_challenge'])

    # Sign challenge

    challenge_signed = generate_signature(sig_alg, sig_key_secret, sig_challenge)
    
    # Decapsulate challenge
    
    kem_challenge_secret = decap_key(kem_alg, kem_key_secret, kem_challenge)    

    # Submit signed challenge

    response = try_register_submit(client, challenge_signed, kem_challenge_secret)

    assert response.status_code == 201
    assert 'message' in response.json
    assert response.json['message'] == 'Registration successful'

def login(client, username, sig_alg, sig_key_secret):
    # Request challenge

    response = client.post('/api/login/challenge', json={
        'username': username,
    })

    assert response.status_code == 200
    assert 'challenge' in response.json

    challenge = base64.b64decode(response.json['challenge'])

    # Sign challenge

    with oqs.Signature(sig_alg, sig_key_secret) as signer:
        challenge_signed = signer.sign(challenge)

    # Submit signed challenge

    response = client.post('/api/login/submit', json={
        'challenge_signed': base64.b64encode(challenge_signed).decode()
    })

    assert response.status_code == 200
    assert 'message' in response.json
    assert response.json['message'] == 'Login successful'

def contact_add(client, sig_alg, sig_key_secret, username):
    # Send contact request
    
    action = '/api/contact/add'    
    timestamp, nonce, signature = sign_data_with_timestamp_and_nonce(sig_alg, sig_key_secret, action, username)

    response = client.post(action, json={
        'signature': base64.b64encode(signature).decode(),
        'timestamp': timestamp,
        'nonce': base64.b64encode(nonce).decode(),
        'action': action,
        'username': username,
    })
    
    print(response.status_code, response.text)

    assert response.status_code == 200
    assert 'message' in response.json
    assert response.json['message'] == 'Contact request sent' \
        or response.json['message'] == 'Contact request accepted'

def contact_remove(client, sig_alg, sig_key_secret, username):
    # Remove contact
    
    action = '/api/contact/remove'
    timestamp, nonce, signature = sign_data_with_timestamp_and_nonce(sig_alg, sig_key_secret, action, username)

    response = client.post(action, json={
        'signature': base64.b64encode(signature).decode(),
        'timestamp': timestamp,
        'nonce': base64.b64encode(nonce).decode(),
        'action': action,
        'username': username,
    })
    
    print(response.status_code, response.text)

    assert response.status_code == 200
    assert 'message' in response.json
    assert response.json['message'] == 'Contact removed' \
        or response.json['message'] == 'Contact request rejected' \
        or response.json['message'] == 'Contact request cancelled'

def contact_request_list(client, sig_alg, sig_key_secret):
    # Get contact requests
    
    action = '/api/contact/requests'  
    timestamp, nonce, signature = sign_data_with_timestamp_and_nonce(sig_alg, sig_key_secret, action)

    response = client.get(action, json={
        'signature': base64.b64encode(signature).decode(),
        'timestamp': timestamp,
        'nonce': base64.b64encode(nonce).decode(),
        'action': action,
    })
    
    print(response.status_code, response.text)

    assert response.status_code == 200
    assert 'requests' in response.json
    assert isinstance(response.json['requests'], list)

    return response.json['requests']

def contact_list(client, sig_alg, sig_key_secret):
    # Get contacts
    
    action = '/api/contact/list'
    timestamp, nonce, signature = sign_data_with_timestamp_and_nonce(sig_alg, sig_key_secret, action)

    response = client.get(action, json={
        'signature': base64.b64encode(signature).decode(),
        'timestamp': timestamp,
        'nonce': base64.b64encode(nonce).decode(),
        'action': action,
    })

    assert response.status_code == 200
    assert 'contacts' in response.json
    assert isinstance(response.json['contacts'], list)

    return response.json['contacts']