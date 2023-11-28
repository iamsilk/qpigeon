import hashlib
import oqs
import struct
from Crypto import Random
from Crypto.Cipher import AES


class AESCipher():
    def __init__(self, key):
        self.bs = AES.block_size
        self.key = hashlib.sha256(key).digest()

    def encrypt(self, raw):
        raw = self._pad(raw)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return iv + cipher.encrypt(raw.encode())

    def decrypt(self, enc):
        iv = enc[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return AESCipher._unpad(cipher.decrypt(enc[AES.block_size:]))

    def _pad(self, s):
        return s + (self.bs - len(s) % self.bs) * chr(self.bs - len(s) % self.bs)

    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s)-1:])]


def decap_key(kem_alg, kem_secret_key, encap_key):
    with oqs.KeyEncapsulation(kem_alg, kem_secret_key) as kem:
        return kem.decap_secret(encap_key)
    

def decrypt_data(kem_alg, kem_secret_key, encap_key, encrypted_data):
    key = decap_key(kem_alg, kem_secret_key, encap_key)
    aes = AESCipher(key)
    data = aes.decrypt(encrypted_data)
    return data


def encap_key(kem_alg, kem_public_key):
    with oqs.KeyEncapsulation(kem_alg) as kem:
        encap_key, key = kem.encap_secret(kem_public_key)
        return encap_key, key


def encrypt_data(kem_alg, kem_public_key, data):
    encrypted_key, key = encap_key(kem_alg, kem_public_key)
    aes = AESCipher(key)
    encrypted_data = aes.encrypt(data)
    return encrypted_key, encrypted_data

def _convert_to_bytes(arg):
    if isinstance(arg, int):
        return arg.to_bytes((arg.bit_length() + 7) // 8, 'big')
    elif isinstance(arg, float):
        return struct.pack("d", arg)
    elif isinstance(arg, bytes):
        return arg
    elif isinstance(arg, str):
        return arg.encode('utf-8')
    else:
        raise Exception('Invalid type')


def verify_signature(sig_alg, sig_public_key, signature, *args):
    # concat args in byte form
    data = b''.join([_convert_to_bytes(arg) for arg in args])

    # verify signature
    with oqs.Signature(sig_alg) as signer:
        return signer.verify(data, signature, sig_public_key)
    

def generate_signature(sig_alg, sig_secret_key, *args):
    # concat args in byte form
    data = b''.join([_convert_to_bytes(arg) for arg in args])

    # sign data
    with oqs.Signature(sig_alg, sig_secret_key) as signer:
        return signer.sign(data)