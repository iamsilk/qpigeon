import base64
import bisect
import datetime
import oqs
import os
import requests

from qpigeon.shared.crypto import generate_signature, verify_signature
from qpigeon.shared.crypto import encap_key, decap_key
from qpigeon.shared.crypto import encrypt_data, decrypt_data


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
    def __init__(self, endpoint):
        self.endpoint = endpoint
        self.session = requests.Session()
        
        self.username = None
        self.logged_in = False
        
        self.sig_alg = None
        self.sig_secret_key = None
        self.sig_public_key = None
        
        self.kem_alg = None
        self.kem_secret_key = None
        self.kem_public_key = None
        self.kem_signature = None
        
        self.nonces = []
        self.known_signatures = {}
        self.known_kems = {}
        
        self.messages = {}
        
        self.callbacks = {
            'new_signature': [],
            'new_kem': []
        }
        
    def load_username(self, username):
        self.username = username

    def load_sig_key(self, sig_alg, sig_secret_key, sig_public_key):
        self.sig_alg = sig_alg
        self.sig_secret_key = sig_secret_key
        self.sig_public_key = sig_public_key
        
    def load_kem_key(self, kem_alg, kem_secret_key, kem_public_key, kem_signature):
        self.kem_alg = kem_alg
        self.kem_secret_key = kem_secret_key
        self.kem_public_key = kem_public_key
        self.kem_signature = kem_signature
        
    def gen_sig_key(self, sig_alg):
        with oqs.Signature(sig_alg) as signer:
            sig_public_key = signer.generate_keypair()
            sig_secret_key = signer.export_secret_key()
            
        self.sig_alg = sig_alg
        self.sig_secret_key = sig_secret_key
        self.sig_public_key = sig_public_key
        
        return sig_secret_key, sig_public_key
    
    def gen_kem_key(self, kem_alg):
        with oqs.KeyEncapsulation(kem_alg) as kem:
            kem_public_key = kem.generate_keypair()
            kem_secret_key = kem.export_secret_key()
            
        self.kem_alg = kem_alg
        self.kem_secret_key = kem_secret_key
        self.kem_public_key = kem_public_key
        
        self.kem_signature = generate_signature(self.sig_alg, self.sig_secret_key, kem_public_key)
        
        return kem_secret_key, kem_public_key

    def generate_nonce(self):
        nonce_length = 32
        return os.urandom(nonce_length)

    def register_new_signature_callback(self, callback):
        self.callbacks['new_signature'].append(callback)
        
    def register_new_kem_callback(self, callback):
        self.callbacks['new_kem'].append(callback)

    def load_known_signatures(self, known_signatures):
        self.known_signatures = known_signatures
    
    def record_new_signature(self, username, sig_alg, sig_public_key, overwrite=False):
        if overwrite:
            self.known_signatures[username] = {
                'sig_alg': sig_alg,
                'sig_public_key': sig_public_key
            }
            return
        
        if username not in self.known_signatures:            
            self.known_signatures[username] = {
                'sig_alg': sig_alg,
                'sig_public_key': sig_public_key
            }
            
            # run callbacks
            for callback in self.callbacks['new_signature']:
                callback(username, sig_alg, sig_public_key)

            return
        
        if self.known_signatures[username]['sig_alg'] == sig_alg and self.known_signatures[username]['sig_public_key'] == sig_public_key:
            return # do nothing
        
        raise ClientError(f"Contact {username} already exists with different signature. Possible tampering detected.")
    
    def load_known_kems(self, known_kems):
        self.known_kems = known_kems
        
    def record_new_kem(self, username, kem_alg, kem_public_key, kem_signature):
        if username not in self.known_signatures:
            raise ClientError(f"Cannot verify {username}'s KEM as they are not a known contact.")
        
        known_sig = self.known_signatures[username]
        
        known_kem = self.known_kems.get(username)
        
        if known_kem and known_kem['kem_alg'] == kem_alg and known_kem['kem_public_key'] == kem_public_key:
            return # do nothing
        
        if not verify_signature(known_sig['sig_alg'],
                                base64.b64decode(known_sig['sig_public_key']),
                                base64.b64decode(kem_signature),
                                base64.b64decode(kem_public_key)):
            raise ClientError(f"KEM signature for {username} is invalid. Possible tampering detected.")
        
        self.known_kems[username] = {
            'kem_alg': kem_alg,
            'kem_public_key': kem_public_key,
            'kem_signature': kem_signature
        }
        
        # run callbacks
        for callback in self.callbacks['new_kem']:
            callback(username, kem_alg, kem_public_key, kem_signature)

    def load_messages(self, messages):
        self.messages = messages
        
        # sort messages by timestamp
        for username, messages in self.messages.items():
            self.messages[username] = sorted(messages, key=lambda x: x['timestamp'])

    def record_message(self, username, incoming, timestamp, nonce, message):
        if username not in self.messages:
            self.messages[username] = []
            
        message_obj = {
            'incoming': incoming,
            'timestamp': timestamp,
            'nonce': nonce,
            'message': message,
        }
        
        if message_obj in self.messages[username]:
            return
        
        if not incoming:
            bisect.insort(self.messages[username], message_obj, key=lambda x: x['timestamp'])
            return
        
        if len(self.messages[username]) > 0 and self.messages[username][-1]['timestamp'] > timestamp:
            raise ClientError("Received message that is older than latest message. Possible tampering detected.")
        
        self.messages[username].append({
            'incoming': incoming,
            'timestamp': timestamp,
            'nonce': nonce,
            'message': message,
        })

    def get_sig_algorithms(self):
        return oqs.get_enabled_sig_mechanisms()
        
    def get_kem_algorithms(self):
        return oqs.get_enabled_kem_mechanisms()

    def register(self, username):
        if not self.sig_alg:
            raise ClientError("Signature algorithm not set.")
        if not self.sig_secret_key:
            raise ClientError("Signature secret key not set.")
        if not self.sig_public_key:
            raise ClientError("Signature public key not set.")
        if not self.kem_alg:
            raise ClientError("KEM algorithm not set.")
        if not self.kem_secret_key:
            raise ClientError("KEM secret key not set.")
        if not self.kem_public_key:
            raise ClientError("KEM public key not set.")
        if not self.kem_signature:
            raise ClientError("KEM signature not set.")
        
        response = self.session.post(self.endpoint + "/api/register/challenge", json={
            'username': username,
            'sig_alg': self.sig_alg,
            'sig_key': base64.b64encode(self.sig_public_key).decode(),
            'kem_alg': self.kem_alg,
            'kem_key': base64.b64encode(self.kem_public_key).decode(),
            'kem_signature': base64.b64encode(self.kem_signature).decode()
        })
        
        _raise_if_bad(response)

        sig_challenge = base64.b64decode(response.json()['sig_challenge'])
        kem_challenge = base64.b64decode(response.json()['kem_challenge'])

        signed_challenge = generate_signature(self.sig_alg, self.sig_secret_key, sig_challenge)
        kem_challenge_secret = decap_key(self.kem_alg, self.kem_secret_key, kem_challenge)
        
        response = self.session.post(self.endpoint + "/api/register/submit", json={
            'challenge_signed': base64.b64encode(signed_challenge).decode(),
            'kem_challenge_secret': base64.b64encode(kem_challenge_secret).decode()
        })

        _raise_if_bad(response)
        
        self.username = username

        return response.status_code == 201

    def login(self, username):
        if not self.sig_alg:
            raise ClientError("Signature algorithm not set.")
        if not self.sig_secret_key:
            raise ClientError("Signature secret key not set.")
        if not self.sig_public_key:
            raise ClientError("Signature public key not set.")
        
        response = self.session.post(self.endpoint + "/api/login/challenge", json={
            'username': username
        })

        _raise_if_bad(response)

        challenge = response.json()['challenge']
        challenge_bytes = base64.b64decode(challenge)

        with oqs.Signature(self.sig_alg, self.sig_secret_key) as signer:
            signed_challenge_bytes = signer.sign(challenge_bytes)
        
        signed_challenge = base64.b64encode(signed_challenge_bytes).decode()

        response = self.session.post(self.endpoint + "/api/login/submit", json={
            'challenge_signed': signed_challenge
        })

        _raise_if_bad(response)
        
        if response.status_code != 200:
            return False
        
        self.username = username
        self.logged_in = True

        return True
    
    def craft_signature(self, *args):
        timestamp = int(datetime.datetime.now(datetime.UTC).timestamp())
        nonce = self.generate_nonce()
        signature = generate_signature(self.sig_alg, self.sig_secret_key, timestamp, nonce, *args)
        return signature, timestamp, nonce

    def get_contacts(self):
        if not self.logged_in:
            raise ClientError("Not logged in.")
        
        action = '/api/contact/list'
        signature, timestamp, nonce = self.craft_signature(action)
        
        response = self.session.get(self.endpoint + action, json={
            'signature': base64.b64encode(signature).decode(),
            'timestamp': timestamp,
            'nonce': base64.b64encode(nonce).decode(),
            'action': action,
        })
        
        _raise_if_bad(response)
        
        contacts = response.json()['contacts']
        
        for contact in contacts:
            self.record_new_signature(contact['username'], contact['sig_alg'], contact['sig_key'])
            self.record_new_kem(contact['username'], contact['kem_alg'], contact['kem_key'], contact['kem_signature'])
        
        return contacts

    def get_contact_requests(self):
        if not self.logged_in:
            raise ClientError("Not logged in.")
        
        action = '/api/contact/requests'
        signature, timestamp, nonce = self.craft_signature(action)
        
        response = self.session.get(self.endpoint + action, json={
            'signature': base64.b64encode(signature).decode(),
            'timestamp': timestamp,
            'nonce': base64.b64encode(nonce).decode(),
            'action': action,
        })
        
        _raise_if_bad(response)
        
        requests = response.json()['requests']
        
        # record new sigs and kems
        for request in requests:
            self.record_new_signature(request['username'], request['sig_alg'], request['sig_key'])
            self.record_new_kem(request['username'], request['kem_alg'], request['kem_key'], request['kem_signature'])
        
        # verify signatures
        for request in requests:
            sig_alg = request['sig_alg']
            sig_key = base64.b64decode(request['sig_key'])
            
            signature = base64.b64decode(request['signed_request']['signature'])
            timestamp = request['signed_request']['timestamp']
            nonce = base64.b64decode(request['signed_request']['nonce'])
            action = request['signed_request']['action']
            username = request['signed_request']['username']
            
            if not verify_signature(sig_alg, sig_key, signature, timestamp, nonce, action, username):
                raise ClientError(f"Message signature for {username} is invalid. Possible tampering detected.")
        
        return requests

    def add_contact(self, username):
        if not self.logged_in:
            raise ClientError("Not logged in.")
        
        action = '/api/contact/add'
        signature, timestamp, nonce = self.craft_signature(action, username)
        
        response = self.session.post(self.endpoint + action, json={
            'signature': base64.b64encode(signature).decode(),
            'timestamp': timestamp,
            'nonce': base64.b64encode(nonce).decode(),
            'action': action,
            'username': username,
        })
        
        _raise_if_bad(response)
        
        if response.status_code != 200:
            return False
        
        return response.json()['message']

    def remove_contact(self, username):
        if not self.logged_in:
            raise ClientError("Not logged in.")
        
        action = '/api/contact/remove'
        signature, timestamp, nonce = self.craft_signature(action, username)
        
        response = self.session.post(self.endpoint + action, json={
            'signature': base64.b64encode(signature).decode(),
            'timestamp': timestamp,
            'nonce': base64.b64encode(nonce).decode(),
            'action': action,
            'username': username,
        })
        
        _raise_if_bad(response)
        
        if response.status_code != 200:
            return False
        
        return response.json()['message']

    def send_message(self, username, message):
        if not self.logged_in:
            raise ClientError("Not logged in.")
        
        if username not in self.known_kems:
            raise ClientError(f"Cannot send message to {username} as they are not a known contact. Try refreshing the contact list.")
        
        known_kem = self.known_kems[username]
        encrypted_key, encrypted_message = encrypt_data(
            known_kem['kem_alg'],
            base64.b64decode(known_kem['kem_public_key']),
            message
        )
        
        action = '/api/message/send'
        signature, timestamp, nonce = self.craft_signature(action, username, encrypted_key, encrypted_message)
        
        response = self.session.post(self.endpoint + action, json={
            'signature': base64.b64encode(signature).decode(),
            'timestamp': timestamp,
            'nonce': base64.b64encode(nonce).decode(),
            'action': action,
            'username': username,
            'encrypted_key': base64.b64encode(encrypted_key).decode(),
            'encrypted_message': base64.b64encode(encrypted_message).decode(),
        })
        
        _raise_if_bad(response)
        
        if response.status_code != 200:
            return False
        
        if username not in self.messages:
            self.messages[username] = []
        
        self.record_message(username, False, timestamp, base64.b64encode(nonce).decode(), message)
        
        return response.json()['message']
    
    def get_messages(self, username):
        if not self.logged_in:
            raise ClientError("Not logged in.")
        
        action = '/api/message/list'
        signature, timestamp, nonce = self.craft_signature(action, username)
        
        response = self.session.get(self.endpoint + action, json={
            'signature': base64.b64encode(signature).decode(),
            'timestamp': timestamp,
            'nonce': base64.b64encode(nonce).decode(),
            'action': action,
            'username': username,
        })
        
        _raise_if_bad(response)
        
        if response.status_code != 200:
            return False
        
        messages = response.json()['messages']
        
        # sort messages by timestamp
        messages.sort(key=lambda x: x['timestamp'])
        
        # decrypt messages
        for message in messages:
            signature = base64.b64decode(message['signature'])
            timestamp = message['timestamp']
            nonce = base64.b64decode(message['nonce'])
            action = message['action']
            encrypted_key = base64.b64decode(message['encrypted_key'])
            encrypted_message = base64.b64decode(message['encrypted_message'])
            
            # check if known signature
            if username not in self.known_signatures:
                raise ClientError(f"No known signature for {username}. Try refreshing contacts.")
            
            # verify signature
            if not verify_signature(self.sig_alg, base64.b64decode(self.known_signatures[username]['sig_public_key']), signature,
                                    timestamp, nonce, action, self.username, encrypted_key, encrypted_message):
                raise ClientError(f"Message signature for {username} is invalid. Possible tampering detected.")
            
            # decrypt message
            message_text = decrypt_data(self.kem_alg, self.kem_secret_key, encrypted_key, encrypted_message).decode('utf-8')
            
            # record message
            self.record_message(username, True, timestamp, base64.b64encode(nonce).decode(), message_text)
        
        return self.messages.get(username, [])