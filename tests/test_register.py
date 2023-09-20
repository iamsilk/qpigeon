import base64
import helpers
import pytest
import re
import test_data

@pytest.mark.parametrize('sig_alg', test_data.enabled_sig_mechanisms)
def test_register_success(sig_alg, client):
    # Generate key
    sig_key_public, sig_key_secret = helpers.generate_keypair(sig_alg)

    # Register
    helpers.register(client, 'user1', sig_alg, sig_key_public, sig_key_secret)

def test_register_user_exists(client):
    # Generate key
    sig_alg = test_data.known_sig_alg
    sig_key_public, sig_key_secret = helpers.generate_keypair(sig_alg)

    # Request challenge
    response = helpers.try_register_challenge(client, test_data.known_username, sig_alg, sig_key_public)

    assert response.status_code == 200
    assert 'challenge' in response.json

    challenge = base64.b64decode(response.json['challenge'])

    # Sign challenge
    challenge_signed = helpers.sign_challenge(sig_alg, sig_key_secret, challenge)

    # Submit signed challenge
    response = client.post('/api/register/submit', json={
        'challenge_signed': base64.b64encode(challenge_signed).decode()
    })

    assert response.status_code == 400
    assert 'message' in response.json
    assert response.json['message'] == 'Username already taken'

@pytest.mark.parametrize(['username', 'sig_alg', 'sig_key_public', 'response_code', 'response_message'], [
    (None, None, None, 400, 'Username required'),
    ('aa', None, None, 400, 'Signature algorithm required'),
    ('aa', 'signature', None, 400, 'Signature key required'),
    ('aa', 'algorithm', '*******', 400, 'Signature key must be base64 encoded'),
    ('aa', 'algorithm', 'dGVzdA==', 400, 'Signature algorithm not enabled'),
    ('aa', test_data.known_sig_alg, 'dGVzdA==', 400, 'Username must be between \\d+ and \\d+ characters'),
    ('username', test_data.known_sig_alg, 'dGVzdA==', 200, None),
    (test_data.known_username, test_data.known_sig_alg, 'dGVzdA==', 200, None)
])
def test_register_submit_input_validation(client, username, sig_alg, sig_key_public, response_code, response_message):
    # Request challenge
    response = helpers.try_register_challenge_raw(client, username, sig_alg, sig_key_public)

    assert response.status_code == response_code
    if response_message:
        assert 'message' in response.json
        assert re.match(response_message, response.json['message'])
    else:
        assert 'challenge' in response.json
        base64.b64decode(response.json['challenge'], validate=True)