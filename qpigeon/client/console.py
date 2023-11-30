import argparse
import base64
import datetime
import os
import json

from client import Client, ClientError

class ConsoleClient():
    def __init__(self, endpoint, profile_dir):
        self.client = Client(endpoint)
        
        self.client.register_new_signature_callback(self.new_signature_callback)
        self.client.register_new_kem_callback(self.new_kem_callback)
        
        self.sig_alg = 'Dilithium2'
        self.kem_alg = 'Kyber512'
        
        self.profile_dir = os.path.abspath(os.path.expanduser(profile_dir))
        
        # make directory if it doesn't exist
        if not os.path.exists(self.profile_dir):
            os.makedirs(self.profile_dir)
        
        self._profile_user_path = os.path.join(self.profile_dir, 'user.json')
        self._profile_contacts_path = os.path.join(self.profile_dir, 'contacts.json')
        self._profile_messages_path = os.path.join(self.profile_dir, 'messages.json')
        
        self.profile_user = {
            'username': None,
            'sig_key': None,
            'kem_key': None
        }
        
    def run(self):
        print('Welcome to qpigeon!')
        print(f'[ Endpoint: {self.client.endpoint}, Profile directory: {self.profile_dir} ]')
        
        self.load_profile()
        
        print('Type "help" for a list of commands')
        
        self.command_loop()
        
        self.save_profile()
        
        print('Goodbye!')
    
    def load_profile(self):
        print('Loading profile...')
        self.load_profile_user()
        self.load_profile_contacts()
        self.load_profile_messages()
        
    def load_profile_user(self):
        try:
            with open(self._profile_user_path, 'r') as f:
                self.profile_user = json.load(f)
                
                username = self.profile_user['username']
                if username:
                    self.client.load_username(username)
                    print(f'- Username: {username}')
                else:
                    print(f'- Username: <not set>')
                
                sig_key = self.profile_user['sig_key']
                if sig_key:
                    sig_alg = sig_key['sig_alg']
                    sig_secret_key = sig_key['sig_secret_key']
                    sig_public_key = sig_key['sig_public_key']
                    self.client.load_sig_key(
                        sig_alg,
                        base64.b64decode(sig_secret_key),
                        base64.b64decode(sig_public_key)
                    )
                    print(f'- Signature: {sig_alg} key loaded.')
                else:
                    print(f'- Signature: <not set>')
                
                kem_key = self.profile_user['kem_key']
                if kem_key:
                    kem_alg = kem_key['kem_alg']
                    kem_secret_key = kem_key['kem_secret_key']
                    kem_public_key = kem_key['kem_public_key']
                    kem_signature = kem_key['kem_signature']
                    self.client.load_kem_key(
                        kem_alg,
                        base64.b64decode(kem_secret_key),
                        base64.b64decode(kem_public_key),
                        base64.b64decode(kem_signature)
                    )
                    print(f'- KEM: {kem_alg} key loaded.')
                else:
                    print(f'- KEM: <not set>')
        except FileNotFoundError:
            print(f'- Username: <not set>')
            print(f'- Signature: <not set>')
            print(f'- KEM: <not set>')
        except json.JSONDecodeError:
            print(f'Error: {self._profile_user_path} is corrupted')
    
    def load_profile_contacts(self):
        try:
            with open(self._profile_contacts_path, 'r') as f:
                contacts = json.load(f)
                known_signatures = contacts['known_signatures']
                known_kems = contacts['known_kems']
                self.client.load_known_signatures(known_signatures)
                self.client.load_known_kems(known_kems)
                print(f'- Known signatures loaded ({len(known_signatures)}).')
                print(f'- Known KEMs loaded ({len(known_kems)}).')
        except FileNotFoundError:
            print('- No known signatures loaded.')
            print('- No known KEMs loaded.')
        except json.JSONDecodeError:
            print(f'Error: {self._profile_contacts_path} is corrupted')
    
    def load_profile_messages(self):
        try:
            with open(self._profile_messages_path, 'r') as f:
                messages = json.load(f)
                self.client.load_messages(messages)
                print(f'- Messages loaded ({len(messages)}).')
        except FileNotFoundError:
            print('- No messages loaded.')
        except json.JSONDecodeError:
            print(f'Error: {self._profile_messages_path} is corrupted')
    
    def save_profile(self):
        self.save_profile_user()
        self.save_profile_contacts()
        self.save_profile_messages()
    
    def save_profile_user(self):
        self.profile_user = {
            'username': self.client.username
        }
        
        if self.client.sig_alg:
            self.profile_user['sig_key'] = {
                'sig_alg': self.client.sig_alg,
                'sig_secret_key': base64.b64encode(self.client.sig_secret_key).decode(),
                'sig_public_key': base64.b64encode(self.client.sig_public_key).decode()
            }
            
        if self.client.kem_alg:
            self.profile_user['kem_key'] = {
                'kem_alg': self.client.kem_alg,
                'kem_secret_key': base64.b64encode(self.client.kem_secret_key).decode(),
                'kem_public_key': base64.b64encode(self.client.kem_public_key).decode(),
                'kem_signature': base64.b64encode(self.client.kem_signature).decode()
            }
        
        with open(self._profile_user_path, 'w') as f:
            json.dump(self.profile_user, f, indent=4)
    
    def save_profile_contacts(self):
        with open(self._profile_contacts_path, 'w') as f:
            json.dump({
                'known_signatures': self.client.known_signatures,
                'known_kems': self.client.known_kems
            }, f, indent=4)
    
    def save_profile_messages(self):
        with open(self._profile_messages_path, 'w') as f:
            json.dump(self.client.messages, f, indent=4)

    def new_signature_callback(self, username, sig_alg, sig_public_key):
        print(f'* First time seeing signature for {username}. Saving to known signatures...')
        self.save_profile_contacts()
        
    def new_kem_callback(self, username, kem_alg, kem_public_key, kem_signature):
        print(f'* First time seeing KEM for {username}. Saving to known KEMs...')
        self.save_profile_contacts()
    
    def command_loop(self):
        while True:
            try:
                try:
                    command = input('qpigeon> ').lower()
                except KeyboardInterrupt:
                    print()
                    break
                
                if command == 'help':
                    print("Available commands:")
                    print(" General:")
                    print("  help      - show this help")
                    print("  quit      - quit the client")
                    print("  algs      - show the enabled post-quantum algorithms")
                    print(" Authentication:")
                    print("  login     - login as the current profile's user")
                    print("  register  - register as new user (WARNING: this may overwrite your existing profile)")
                    print(" Contacts:")
                    print("  add       - add a new contact or accept a contact request")
                    print("  remove    - remove a contact or reject a contact request")
                    print("  contacts  - list contacts")
                    print("  requests  - list contact requests")
                    print(" Messaging:")
                    print("  send      - send a message to a contact")
                    print("  messages  - view messages from a contact")
                    continue
                
                if command == 'quit':
                    break
                
                if command == 'algs':
                    self.print_algorithms()
                    continue
                
                if command == 'login':
                    self.login()
                    continue
                
                if command == 'register':
                    self.register()
                    continue
                
                if command == 'add':
                    self.add_contact()
                    continue
                
                if command == 'remove':
                    self.remove_contact()
                    continue
                
                if command == 'contacts':
                    self.list_contacts()
                    continue
                
                if command == 'requests':
                    self.list_requests()
                    continue
                
                if command == 'send' or command == 'message':
                    self.send_message()
                    continue
                
                if command == 'messages':
                    self.list_messages()
                    continue
                
                print(f'Unknown command: {command}')
            except ClientError as e:
                print(f'Error: {e}')
            except KeyboardInterrupt:
                print()
                continue
            
    def print_algorithms(self):
        print("Available signature algorithms (*selected):")
        sig_algorithms = self.client.get_sig_algorithms()
        sig_algorithms = [('*' + alg) if alg == self.sig_alg else alg for alg in self.client.get_sig_algorithms()]
        print('  ' + ', '.join(sig_algorithms))
        print()
        
        print("Available KEM algorithms (*selected):")
        kem_algorithms = self.client.get_kem_algorithms()
        kem_algorithms = [('*' + alg) if alg == self.kem_alg else alg for alg in self.client.get_kem_algorithms()]
        print('  ' + ', '.join(kem_algorithms))
        print()

    def login(self):
        username = self.client.username or input('Username> ')
        print('Logging in...')
        if self.client.login(username):
            print('Login successful!')
        else:
            print('Login failed!')
    
    def register(self):
        username = input('Username> ')
        
        # TODO: Make this configurable
        sig_alg = 'Dilithium2'
        kem_alg = 'Kyber512'
        
        print('Generating signature key...')
        self.client.gen_sig_key(sig_alg)
        
        print('Generating KEM key...')
        self.client.gen_kem_key(kem_alg)
        
        print(f'Registering account {username}...')
        
        if self.client.register(username):
            self.save_profile_user()            
            print('Registration successful! You may now login.')
        else:
            print('Registration failed!')
    
    def add_contact(self):
        username = input('Contact Username> ')
        result = self.client.add_contact(username)
        if not result:
            print('Error occurred while adding contact.')
            return
        
        # force update contact list
        self.client.get_contacts()
        
        print(result)
    
    def remove_contact(self):
        username = input('Contact Username> ')
        result = self.client.remove_contact(username)
        if not result:
            print('Error occurred while removing contact.')
            return
        
        # force update contact list
        self.client.get_contacts()
        
        print(result)
    
    def list_contacts(self):
        contacts = self.client.get_contacts()
        print(f'Contacts ({len(contacts)}):')
        for contact in contacts:
            print(f'- Username: {contact['username']}')
    
    def list_requests(self):
        requests = self.client.get_contact_requests()
        print(f'Contact requests ({len(requests)}):')
        for request in requests:
            print(f'- Username: {request['username']}')
    
    def send_message(self):
        username = input('Contact Username> ')
        message = input('Message> ')
        result = self.client.send_message(username, message)
        if not result:
            print('Error occurred while sending message.')
            return
        print(result)
    
    def list_messages(self):
        username = input('Contact Username> ')
        messages = self.client.get_messages(username)
        if not messages:
            print(f'Unable to get messages for {username}')
            return
        
        print(f'Conversation with {username} ({len(messages)}):')
        for message in messages:
            message_username = username if message['incoming'] else self.client.username
            message_time = datetime.datetime.fromtimestamp(message['timestamp'], datetime.UTC).strftime('%Y-%m-%d %H:%M:%S')
            print(f'- {message_username} at {message_time}')
            print(f'  {message['message']}')
            
    

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Qpigeon client')
    parser.add_argument('-e', '--endpoint', dest='endpoint', default='http://localhost:5000', help='qpigeon server endpoint')
    parser.add_argument('-p', '--profile', dest='profile', default='~/.qpigeon', help='qpigeon profile directory')
    args = parser.parse_args()
    
    client = ConsoleClient(args.endpoint, args.profile)
    client.run()