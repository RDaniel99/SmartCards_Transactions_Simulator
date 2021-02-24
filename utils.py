from Cryptodome.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
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
