from Cryptodome.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

import binascii
import os.path
from os import path


def generate_paths(is_client):
    if is_client:
        owner = "client"
    else:
        owner = "merchant"

    private_key_path = "keys/" + owner + "_private_key.pem"
    public_key_path = "keys/" + owner + "_public_key.pem"

    return private_key_path, public_key_path


def generate_keys(is_client):
    private_key_path, public_key_path = generate_paths(is_client)

    if not path.exists(private_key_path):
        private_key = RSA.generate(1024)
        f = open(private_key_path, 'wb')
        f.write(private_key.export_key('PEM'))
        f.close()

    if not path.exists(public_key_path):
        f = open(private_key_path, 'r')
        private_key = RSA.import_key(f.read())
        public_key = private_key.publickey()
        f = open(public_key_path, 'wb')
        f.write(public_key.export_key('PEM'))
        f.close()

    private_key = load_private_keys(is_client)
    public_key = load_public_keys(is_client)

    return private_key, public_key


def load_private_keys(is_client):
    private_key_path, public_key_path = generate_paths(is_client)
    f = open(private_key_path, 'r')
    private_key = f.read()
    f.close()

    return private_key


def load_public_keys(is_client):
    private_key_path, public_key_path = generate_paths(is_client)
    f = open(public_key_path, 'r')
    public_key = f.read()
    f.close()

    return public_key


def decrypt_aes(key, msg, iv):
    cipher = AES.new(key, AES.MODE_CFB, iv)
    plaintext = cipher.decrypt(msg)
    return plaintext.decode('utf-8')


def decrypt_rsa(path_key, ciphertext):
    key = RSA.importKey(open(path_key).read())
    cipher = PKCS1_OAEP.new(key)
    return cipher.decrypt(ciphertext)


def hybrid_encryption(messages, digital_envelope):
    encrypted_messages = []
    for message in messages:
        encrypted_symmetric_key, encrypted_message, symmetric_session_key, iv = hybrid_encryption_individual(message,
                                                                                      digital_envelope)
        encrypted_messages.append([encrypted_symmetric_key, encrypted_message, symmetric_session_key, iv])

    return encrypted_messages


def hybrid_encryption_individual(message, digital_envelope):
    symmetric_session_key = get_random_bytes(32)
    iv = get_random_bytes(16)

    cipher_asymmetric = PKCS1_OAEP.new(RSA.import_key(digital_envelope))
    encrypted_symmetric_key = cipher_asymmetric.encrypt(symmetric_session_key)

    cipher_symmetric = AES.new(symmetric_session_key, AES.MODE_CFB, iv)

    encrypted_message = cipher_symmetric.encrypt(bytes(message, encoding='utf-8'))
    return encrypted_symmetric_key, encrypted_message, symmetric_session_key, iv


def get_signature():
    private_key = load_private_keys(False)
    sid = get_random_bytes(8)

    sid_hash = SHA256.new(sid)
    key = RSA.import_key(private_key)

    signed_hash = pkcs1_15.new(key). \
        sign(sid_hash)

    return sid, signed_hash
