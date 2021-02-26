import base64

from constants import ADDRESS_CM
from constants import ADDRESS_MC
import pickle
from node import Node
from node import new_listener
from node import new_sender
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import string
import random
from os import path
import os.path
import utils as utils
import crypto_utils as crypto_utils
import keys_utils as keys_utils


keys_utils.generate_keys("client")

merchant_public_key = keys_utils.load_public_keys("merchant")
client_public_key = keys_utils.load_public_keys("client")
client_private_key = keys_utils.load_private_keys("client")

# Hybrid encryption of a message m with the key k means that the message m is encrypted using a symmetric session key
# s, which is in turn encrypted using an asymmetric key k (the digital envelope).
encrypted_symmetric_key, encrypted_message, symmetric_session_key, iv = crypto_utils.hybrid_encryption_individual(
    bytes(client_public_key, encoding='utf-8'), bytes(merchant_public_key, encoding='utf-8'))

print("-------------")
print(client_public_key)

core = Node()
core.add_sender(new_sender(ADDRESS_CM), ADDRESS_CM)
core.send_message_to_address(ADDRESS_CM, iv)
core.send_message_to_address(ADDRESS_CM, encrypted_symmetric_key)
core.send_message_to_address(ADDRESS_CM, encrypted_message)
core.close_connection(ADDRESS_CM)

core.add_listener(new_listener(ADDRESS_MC), ADDRESS_MC)
core.accept_connection(ADDRESS_MC)
encrypted_messages = core.receive_message(ADDRESS_MC)
core.close_connection(ADDRESS_MC)

sid_and_signature = []

for encrypted_message in encrypted_messages:
    encrypted_symmetric_key, message, iv = encrypted_message
    K = crypto_utils.decrypt_rsa(client_private_key, encrypted_symmetric_key)
    m = crypto_utils.decrypt_aes(K, message, iv)
    print("-------------")
    print(m)
    sid_and_signature.append(m)

#-------------------

digits = string.digits
card_number = utils.get_random_string(10)
card_exp = utils.get_random_string(2) + "/" + utils.get_random_string(2)
ccode = utils.get_random_string(3)
amount = utils.get_random_string(4) + " euro"
nc = utils.get_random_string(5)
merchant_name = "Moda Operandi"

messages = dict()
messages["card_number"] = card_number
messages["card_exp"] = card_exp
messages["ccode"] = ccode
messages["sid"] = sid_and_signature[0]
messages["amount"] = amount
messages["pubKC"] = client_public_key
messages["nc"] = nc
messages["m"] = merchant_name

print(messages)
PI = list(messages.values())

PI_bytes = pickle.dumps(PI)
print("pi: ", pickle.loads(PI_bytes))

signature = pkcs1_15.new(RSA.import_key(client_private_key)).sign(SHA256.new(PI_bytes))
PM = (PI, signature)
print("signature: ", base64.b64encode(signature).decode())

f = open("keys/payment_gateway_public_key.pem", 'r')
payment_gateway_public_key = f.read()
f.close()

f = open("keys/payment_gateway_private_key.pem", 'r')
payment_gateway_private_key = f.read()
f.close()

PI_PM = [PI_bytes, signature]

# encrypted_messages = utils.hybrid_encryption(PI_PM, payment_gateway_public_key)
