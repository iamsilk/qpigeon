import requests
from tests.helpers import generate_keypair, sign_challenge
import secrets
import base64
import json
import os
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

session = requests.Session()

def verify_user(_url, _json_data):
    # Verify challenge function here?
    _response = session.post(_url + "/challenge", data=_json_data, headers=headers)

    _challenge = _response.json()['challenge']

    # Verifying the signature
    _signed_challenge = sign_challenge(sig_alg, sig_key_secret, base64.b64decode(_challenge))

    _data = {'challenge_signed': base64.b64encode(_signed_challenge).decode()}
    _json_data = json.dumps(_data)

    # Make the POST request
    _response = session.post(_url + "/submit", data=_json_data, headers=headers)

    print(_response.json()['message'])

    return _response.status_code


def generate_nonce(_pskey):
    _nonce = base64.b64encode(secrets.token_bytes(16)).decode()

    if not os.path.exists(nonces_file):
        f = open(nonces_file, "w+")
        _json_data = {
            'sig_pub_key': base64.b64encode(_pskey).decode(),
            'nonces':
            [
                {
                    'nonce': _nonce
                }
            ]
        }
        json.dump(_json_data, f, indent=2)

        f.close()

    else:
        f = open(nonces_file, "r+")
        json_str = f.read()
        existing_nonces = json.loads(json_str)
        if existing_nonces['sig_pub_key'] == base64.b64encode(_pskey).decode():
            found = any(e['nonce'] == _nonce for e in existing_nonces['nonces'])

            if not found:
                existing_nonces['nonces'].append({'nonce': _nonce})
                f.seek(0)
                json.dump(existing_nonces, f, indent=2)

        f.close()


    # -- Need to get public key first through requests
    # def add_contact(_contact_username):
    # if not os.path.exists(contacts_file):
    #     f = open(contacts_file, "w+")
    #     _json_data = {
    #         [
    #             {'sender_key': },
    #             {'receiver_key': base64.b64encode(sig_key_public).decode()}
    #         ]
    #     }
    #     json.dump(_json_data, f, indent=2)
    #
    #     f.close()
    #
    # else:
    #     f = open(nonces_file, "r+")
    #     json_str = f.read()
    #     existing_nonces = json.loads(json_str)
    #     if existing_nonces['sig_pub_key'] == base64.b64encode(_pskey).decode():
    #         found = any(e['nonce'] == _nonce for e in existing_nonces['nonces'])
    #
    #         if not found:
    #             existing_nonces['nonces'].append({'nonce': _nonce})
    #             f.seek(0)
    #             json.dump(existing_nonces, f, indent=2)
    #
    #     f.close()


def send_request(_username):
    generate_nonce(sig_key_public)
    # TODO: Send nonce here as well
    request_send_data = json.dumps({'username': _username})
    request_send_response = session.post(request_send_url, data=request_send_data, headers=headers)
    print(request_send_response.json()['message'])


def receive_requests():
    request_send_response = session.get(request_url, headers=headers)
    return request_send_response.json()['requests']


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
            print('[(s)end contact request, (r)eceive requests, (v)iew messages, send (m)essage, e(x)it')
            cmd = input().lower()
            while cmd != 'x':
                while (cmd != 's' and cmd != 'r' and cmd != 'v' and cmd != 'm') or cmd == ' ' or cmd == '\n':
                    print('Enter a valid command')
                    cmd = input().lower()

                if cmd == 's':
                    sendto = input('Send request to: ')
                    send_request(sendto)

                elif cmd == 'r':
                    pending_requests = receive_requests()
                    for r in range(0, len(pending_requests)):
                        print('{}: username = {}', pending_requests[r]['username'])

                elif cmd == 'm':
                    sendto = input('Send message to: ')
                    send_message(sendto)

                print('\nEnter a command: ')
                print('[(s)end contact request, (r)eceive requests, (v)iew messages, send (m)essage, e(x)it')
                cmd = input().lower()

            exit(0)

    print('\nPlease enter a command: ')
    print('[Register (r), Login (l), Exit (x)]')

    cmd = input().lower()
