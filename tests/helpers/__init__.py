import oqs
import base64

def generate_keypair(sig_alg):
    with oqs.Signature(sig_alg) as signer:
        sig_key_public = signer.generate_keypair()
        sig_key_secret = signer.export_secret_key()

    return sig_key_public, sig_key_secret

def sign_challenge(sig_alg, sig_key_secret, challenge):
    with oqs.Signature(sig_alg, sig_key_secret) as signer:
        return signer.sign(challenge)

def try_register_challenge(client, username, sig_alg, sig_key_public):
    return try_register_challenge_raw(client, username, sig_alg, base64.b64encode(sig_key_public).decode())

def try_register_challenge_raw(client, username, sig_alg, sig_key_public):
    data = {}
    if username:
        data['username'] = username
    if sig_alg:
        data['sig_alg'] = sig_alg
    if sig_key_public:
        data['sig_key'] = sig_key_public

    return client.post('/api/register/challenge', json=data)

def try_register_submit(client, challenge_signed):
    data = {}
    if challenge_signed:
        data['challenge_signed'] = base64.b64encode(challenge_signed).decode()

    return client.post('/api/register/submit', json=data)

def register(client, username, sig_alg, sig_key_public, sig_key_secret):
    # Request challenge

    response = try_register_challenge(client, username, sig_alg, sig_key_public)

    assert response.status_code == 200
    assert 'challenge' in response.json

    challenge = base64.b64decode(response.json['challenge'])

    # Sign challenge

    with oqs.Signature(sig_alg, sig_key_secret) as signer:
        challenge_signed = signer.sign(challenge)

    # Submit signed challenge

    response = try_register_submit(client, challenge_signed)

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

def contact_request_send(client, username):
    # Send contact request

    response = client.post('/api/contact/request/send', json={
        'username': username,
    })

    assert response.status_code == 200
    assert 'message' in response.json
    assert response.json['message'] == 'Contact request sent'

def contact_request_list(client):
    # Get contact requests

    response = client.get('/api/contact/request')

    assert response.status_code == 200
    assert 'requests' in response.json
    assert isinstance(response.json['requests'], list)

    return response.json['requests']

def contact_request_accept(client, username):
    # Accept contact request

    response = client.post('/api/contact/request', json={
        'username': username,
    })

    assert response.status_code == 200
    assert 'message' in response.json
    assert response.json['message'] == 'Contact request accepted'

def contact_request_reject(client, username):
    # Reject contact request

    response = client.delete('/api/contact/request', json={
        'username': username,
    })

    assert response.status_code == 200
    assert 'message' in response.json
    assert response.json['message'] == 'Contact request rejected'

def contact_list(client):
    # Get contacts

    response = client.get('/api/contact')

    assert response.status_code == 200
    assert 'contacts' in response.json
    assert isinstance(response.json['contacts'], list)

    return response.json['contacts']

def contact_remove(client, username):
    # Remove contact

    response = client.delete('/api/contact', json={
        'username': username,
    })

    assert response.status_code == 200
    assert 'message' in response.json
    assert response.json['message'] == 'Contact removed'