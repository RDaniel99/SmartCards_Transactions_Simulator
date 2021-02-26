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


def get_random_string(length):
    letters = string.digits
    result_str = ''.join(random.choice(letters) for i in range(length))

    return result_str


utils.generate_keys(True)

merchant_public_key = utils.load_public_keys(False)
client_public_key = utils.load_public_keys(True)
client_private_key = utils.load_private_keys(True)

# Hybrid encryption of a message m with the key k means that the message m is encrypted using a symmetric session key
# s, which is in turn encrypted using an asymmetric key k (the digital envelope).
encrypted_symmetric_key, encrypted_message, symmetric_session_key, iv = utils.hybrid_encryption_individual(
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
    K = utils.decrypt_rsa(client_private_key, encrypted_symmetric_key)
    m = utils.decrypt_aes(K, message, iv)
    print("-------------")
    print(m)
    sid_and_signature.append(m)

#-------------------
digits = string.digits
card_number = get_random_string(10)
card_exp = get_random_string(2) + "/" + get_random_string(2)
ccode = get_random_string(3)
amount = get_random_string(4) + " euro"
nc = get_random_string(5)
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
#
# core.add_listener(new_listener(ADDRESS_MC), ADDRESS_MC)
# core.accept_connection(ADDRESS_MC)
# print(core.receive_message(ADDRESS_MC))
# core.close_connection(ADDRESS_MC)
