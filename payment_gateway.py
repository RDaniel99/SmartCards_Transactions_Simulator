from Cryptodome.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import base64

from os import path

owner = "payment_gateway"

private_key_path = "keys/" + owner + "_private_key.pem"
public_key_path = "keys/" + owner + "_public_key.pem"

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