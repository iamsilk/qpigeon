import base64
import helpers
import pytest
import re
import test_data
from qpigeon.shared.crypto import generate_signature, decap_key

@pytest.mark.parametrize(['sig_alg', 'kem_alg'], [
    (
        test_data.enabled_sig_mechanisms[i % len(test_data.enabled_sig_mechanisms)],
        test_data.enabled_kem_mechanisms[i % len(test_data.enabled_kem_mechanisms)]
    ) for i in range(max(len(test_data.enabled_sig_mechanisms), len(test_data.enabled_kem_mechanisms)))
])
def test_register_success(sig_alg, kem_alg, client):
    # Generate key
    sig_key_public, sig_key_secret = helpers.generate_sig_keypair(sig_alg)
    kem_key_public, kem_key_secret = helpers.generate_kem_keypair(kem_alg)
    kem_key_signature = helpers.sign_kem(kem_key_public, sig_alg, sig_key_secret)

    # Register
    helpers.register(client, 'user1', sig_alg, sig_key_public, sig_key_secret,
                     kem_alg, kem_key_public, kem_key_secret, kem_key_signature)

def test_register_user_exists(client):
    # Generate key
    sig_alg = test_data.known_sig_alg
    kem_alg = test_data.known_kem_alg
    sig_key_public, sig_key_secret = helpers.generate_sig_keypair(sig_alg)
    kem_key_public, kem_key_secret = helpers.generate_kem_keypair(kem_alg)
    kem_key_signature = helpers.sign_kem(kem_key_public, sig_alg, sig_key_secret)

    # Request challenge
    response = helpers.try_register_challenge(client, test_data.known_username, sig_alg, sig_key_public,
                                              kem_alg, kem_key_public, kem_key_signature)

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
    response = client.post('/api/register/submit', json={
        'challenge_signed': base64.b64encode(challenge_signed).decode(),
        'kem_challenge_secret': base64.b64encode(kem_challenge_secret).decode()
    })

    assert response.status_code == 400
    assert 'message' in response.json
    assert response.json['message'] == 'Username already taken'

@pytest.mark.parametrize(['username', 'sig_alg', 'sig_key_public', 'kem_alg', 'kem_key_public', 'kem_signature', 'response_code', 'response_message'], [
    (None, None, None, None, None, None, 400, 'Username required'),
    ('aa', None, None, None, None, None, 400, 'Signature algorithm required'),
    ('aa', 'signature', None, None, None, None, 400, 'Signature key required'),
    ('aa', 'algorithm', '*******', None, None, None, 400, 'KEM algorithm required'),
    ('aa', 'algorithm', '*******', 'algorithm', None, None, 400, 'KEM key required'),
    ('aa', 'algorithm', '*******', 'algorithm', '*******', None, 400, 'KEM signature required'),
    ('aa', 'algorithm', '*******', 'algorithm', '*******', '*******', 400, 'Signature key must be base64 encoded'),
    ('aa', 'algorithm', 'dGVzdA==', 'algorithm', '*******', '*******', 400, 'KEM key must be base64 encoded'),
    ('aa', 'algorithm', 'dGVzdA==', 'algorithm', 'dGVzdA==', '*******', 400, 'KEM signature must be base64 encoded'),
    ('aa', 'algorithm', 'dGVzdA==', 'algorithm', 'dGVzdA==', 'dGVzdA==', 400, 'Signature algorithm not enabled'),
    ('aa', test_data.known_sig_alg, 'dGVzdA==', 'algorithm', 'dGVzdA==', 'dGVzdA==', 400, 'KEM algorithm not enabled'),
    ('aa', test_data.known_sig_alg, 'dGVzdA==', test_data.known_kem_alg, 'dGVzdA==', 'dGVzdA==', 400, 'Username must be between \\d+ and \\d+ characters'),
    ('username', test_data.known_sig_alg, 'dGVzdA==', test_data.known_kem_alg, 'dGVzdA==', 'dGVzdA==', 200, None),
    (test_data.known_username, test_data.known_sig_alg, 'dGVzdA==', test_data.known_kem_alg, 'dGVzdA==', 'dGVzdA==', 200, None),
])
def test_register_submit_input_validation(client, username, sig_alg, sig_key_public,
                                          kem_alg, kem_key_public, kem_signature,
                                          response_code, response_message):
    # Request challenge
    response = helpers.try_register_challenge_raw(client, username, sig_alg, sig_key_public, kem_alg, kem_key_public, kem_signature)

    print(response.status_code, response.text)

    assert response.status_code == response_code
    if response_message:
        assert 'message' in response.json
        assert re.match(response_message, response.json['message'])
    else:
        assert 'sig_challenge' in response.json
        assert 'kem_challenge' in response.json
        base64.b64decode(response.json['sig_challenge'], validate=True)
        base64.b64decode(response.json['kem_challenge'], validate=True)