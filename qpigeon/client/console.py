import requests
from tests.helpers import generate_keypair, sign_data
import secrets
import base64
import json
import os
import time

ss_key_file = os.path.join(os.getcwd(), ".dl2", "ss.dl2")
ps_key_file = os.path.join(os.getcwd(), ".dl2", "ps.dl2")
nonces_file = os.path.join(os.getcwd(), "nonces.json")
contacts_file = os.path.join(os.getcwd(), "contacts.json")

# Dilitihum2 - for now
sig_alg = 'Dilithium2'

# Setting signature key pair
sig_key_public, sig_key_secret = "", ""
user_exists = False

if not os.path.exists(ss_key_file):
    os.makedirs(os.path.join(os.getcwd(), ".dl2/"))
    sig_key_public, sig_key_secret = generate_keypair(sig_alg)

    with open(ss_key_file, "wb+") as file:
        file.write(sig_key_secret)

    with open(ps_key_file, "wb+") as file:
        file.write(sig_key_public)
else:
    user_exists = True
    with open(ss_key_file, "rb+") as file:
        sig_key_secret = file.read()
    with open(ps_key_file, "rb+") as file:
        sig_key_public = file.read()

static_domain = 'https://keen-arguably-termite.ngrok-free.app'

# Assuming the Flask server is running at http://localhost:5000
register_url = static_domain + '/api/register/'
login_url = static_domain + '/api/login/'
request_send_url = static_domain + '/api/contact/request/send'
request_url = static_domain + '/api/contact/request'
contacts_url = static_domain + '/api/contact'

session = requests.Session()


def verify_user(_url, _json_data):
    # Verify challenge function here?
    _response = session.post(_url + "/challenge", data=_json_data, headers=headers)

    _challenge = _response.json()['challenge']

    # Verifying the signature
    _signed_challenge = sign_data(sig_alg, sig_key_secret, base64.b64decode(_challenge))

    _data = {'challenge_signed': base64.b64encode(_signed_challenge).decode()}
    _json_data = json.dumps(_data)

    # Make the POST request
    _response = session.post(_url + "/submit", data=_json_data, headers=headers)

    print(_response.json()['message'])

    return _response.status_code


def generate_nonce(_pskey):
    if not os.path.exists(nonces_file):
        _nonce = base64.b64encode(secrets.token_bytes(16)).decode()
        f = open(nonces_file, "w+")
        _json_data = [{
            'sig_pub_key': base64.b64encode(_pskey).decode(),
            'nonce': _nonce
        }]
        json.dump(_json_data, f, indent=2)

        f.close()

        return _nonce

    else:
        f = open(nonces_file, "r+")
        json_str = f.read()
        existing_nonces = json.loads(json_str)
        while True:
            _nonce = base64.b64encode(secrets.token_bytes(16)).decode()
            nonce_found = False
            for pair in existing_nonces:
                if pair['sig_pub_key'] == base64.b64encode(_pskey).decode():
                    if pair['nonce'] == _nonce and not nonce_found:
                        nonce_found = True

            if not nonce_found:
                break

        existing_nonces.append({'sig_pub_key': base64.b64encode(_pskey).decode(), 'nonce': _nonce})
        f.seek(0)
        json.dump(existing_nonces, f, indent=2)

        f.close()

        return _nonce


def generate_contact(_contact_request):
    if not os.path.exists(contacts_file):
        f = open(contacts_file, "w+")
        _json_data = [{
            'sender_key': _contact_request['sig_key'],
            'receiver_key': base64.b64encode(sig_key_public).decode()
        }]
        json.dump(_json_data, f, indent=2)

        f.close()

        return True

    else:
        f = open(contacts_file, "r+")
        json_str = f.read()
        existing_contacts = json.loads(json_str)
        _contact_key = _contact_request['sig_key']
        contact_found = False
        for pair in existing_contacts:
            if pair['sender_key'] == _contact_key:
                if pair['receiver_key'] == base64.b64encode(sig_key_public).decode() and not contact_found:
                    contact_found = True

        if not contact_found:
            existing_contacts.append({'sender_key': base64.b64encode(sig_key_public).decode(),
                                      'receiver_key': _contact_key})
            f.seek(0)
            json.dump(existing_contacts, f, indent=2)

            f.close()

            return True

        return False


# -- Need to get public key first through requests
def add_contact(_contact_request):
    if generate_contact(_contact_request):
        add_contact_data = json.dumps({'username': _contact_request['username']})
        add_contact_response = session.post(request_url, data=add_contact_data, headers=headers)
        print(add_contact_response.json()['message'])
    else:
        print('Contact already exists')
        delete_request_data = json.dumps({'username': _contact_request['username']})
        delete_request_response = session.delete(request_url, data=delete_request_data, headers=headers)
        print(delete_request_response.json()['message'])


def send_request(_username):
    new_nonce = generate_nonce(sig_key_public)
    # TODO: Send nonce here as well - and timestamp
    time_stamp = time.time()
    request_send_data = json.dumps({'username': _username, 'timestamp': time_stamp, 'nonce': new_nonce})
    request_send_response = session.post(request_send_url, data=request_send_data, headers=headers)
    print(request_send_response.json()['message'])


def receive_requests():
    request_receive_response = session.get(request_url, headers=headers)
    return request_receive_response.json()['requests']


def receive_contacts():
    contact_receive_response = session.get(contacts_url, headers=headers)
    return contact_receive_response.json()['contacts']


def send_message(_username):
    print("Message sent")


# Get input from the user

print('Welcome to qpigeon!')
print('A secret key will be needed for communication and will be stored in the enclosing folder')
print('Please enter a command: ')
print('[Register (r), Login (l), Exit (x)]')

cmd = input().lower()

while cmd != 'x':
    while (cmd != 'r' and cmd != 'l') or cmd == ' ':
        print('Enter a valid command')
        cmd = input().lower()

    username = input('Enter username: ')

    # Data to be sent in the POST request
    data = {'username': username, 'sig_alg': sig_alg}

    # Convert the data to JSON format
    json_data = json.dumps(data)

    # Set the headers for the request
    headers = {'Content-Type': 'application/json'}

    response = ""

    if cmd == 'r' and not user_exists:
        data['sig_key'] = base64.b64encode(sig_key_public).decode()
        json_data = json.dumps(data)

        verify_user(register_url, json_data)

    elif cmd == 'r':
        # TODO: Make it so that there are different keys stored with different users
        print('Public key already exists')

    elif cmd == 'l':
        code = verify_user(login_url, json_data)
        if code == 200:
            print('\nEnter a command: ')
            print('[(s)end contact request, (r)eceive requests, view (c)ontacts' +
                  ', (v)iew messages, send (m)essage, e(x)it')
            cmd = input().lower()
            while cmd != 'x':
                while ((cmd != 's' and cmd != 'r' and cmd != 'v' and cmd != 'm' and cmd != 'c')
                       or cmd == ' ' or cmd == '\n'):
                    print('Enter a valid command')
                    cmd = input().lower()

                if cmd == 's':
                    sendto = input('Send request to: ')
                    send_request(sendto)

                elif cmd == 'r':
                    pending_requests = receive_requests()
                    for r in range(0, len(pending_requests)):
                        print('{}: username = {}'.format(r, pending_requests[r]['username']))

                    if len(pending_requests) > 0:
                        index = int(input('Enter a request to accept: '))

                        add_contact(pending_requests[index])

                elif cmd == 'c':
                    contacts = receive_contacts()

                    for r in range(0, len(contacts)):
                        print('{}: username = {}'.format(r, contacts[r]['username']))

                elif cmd == 'm':
                    sendto = input('Send message to: ')
                    send_message(sendto)

                print('\nEnter a command: ')
                print('[(s)end contact request, (r)eceive requests, (v)iew messages, view (c)ontacts' +
                      'send (m)essage, e(x)it')
                cmd = input().lower()

            exit(0)

    print('\nPlease enter a command: ')
    print('[Register (r), Login (l), Exit (x)]')

    cmd = input().lower()
