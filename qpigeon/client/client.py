import base64
import oqs
import requests


class ClientError(Exception):
    def __init__(self, message):
        self.message = message


def _raise_if_bad(response):
    # known error
    if response.status_code == 400:
        raise ClientError(response.json()['message'])
    
    # unknown error
    response.raise_for_status()


class Client():
    def __init__(self, api_url):
        self.api_url = api_url
        self.session = requests.Session()

    def generate_nonce():
        pass

    def register(self, username, sig_alg, public_key, secret_key):
        response = self.session.post(self.api_url + "/register/challenge", json={
            'username': username,
            'sig_alg': sig_alg,
            'sig_key': base64.b64encode(public_key).decode()
        })
        
        _raise_if_bad(response)

        challenge = response.json()['challenge']
        challenge_bytes = base64.b64decode(challenge)

        with oqs.Signature(sig_alg, secret_key) as signer:
            signed_challenge_bytes = signer.sign(challenge_bytes)
        
        signed_challenge = base64.b64encode(signed_challenge_bytes).decode()

        response = self.session.post(self.api_url + "/register/submit", json={
            'challenge_signed': signed_challenge
        })

        _raise_if_bad(response)

        return response.status_code == 201

    def login(self, username, sig_alg, secret_key):
        response = self.session.post(self.api_url + "/login/challenge", json={
            'username': username
        })

        _raise_if_bad(response)

        challenge = response.json()['challenge']
        challenge_bytes = base64.b64decode(challenge)

        with oqs.Signature(sig_alg, secret_key) as signer:
            signed_challenge_bytes = signer.sign(challenge_bytes)
        
        signed_challenge = base64.b64encode(signed_challenge_bytes).decode()

        response = self.session.post(self.api_url + "/login/submit", json={
            'challenge_signed': signed_challenge
        })

        _raise_if_bad(response)

        return response.status_code == 200

    def get_contacts():
        pass

    def get_contact_requests():
        pass

    def send_contact_request(username):
        pass

    def accept_contact_request(username):
        pass

    def reject_contact_request(username):
        pass

    def send_message(username, message):
        pass