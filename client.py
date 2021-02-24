import base64

from constants import ADDRESS_CM
from constants import ADDRESS_MC
from node import Node
from node import new_listener
from node import new_sender
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from os import path
import os.path
import utils as utils
from Crypto.Random import get_random_bytes

utils.generate_keys(True)

merchant_public_key = utils.load_public_keys(False)
client_public_key = utils.load_public_keys(True)

# Hybrid encryption of a message m with the key k means that the message m is encrypted using a symmetric session key
# s, which is in turn encrypted using an asymmetric key k (the digital envelope).

symmetric_session_key = get_random_bytes(32)
iv = get_random_bytes(16)

cipher_asymmetric = PKCS1_OAEP.new(RSA.import_key(merchant_public_key))
encrypted_symmetric_key = cipher_asymmetric.encrypt(symmetric_session_key)

ind_1 = client_public_key.find('\n')
ind_2 = client_public_key.rfind('\n')
client_public_key = client_public_key[ind_1+1:ind_2]

print(client_public_key)
print("-------------")

cipher = AES.new(symmetric_session_key, AES.MODE_CFB, iv)
ciphertext = cipher.encrypt(bytes(client_public_key, encoding='utf-8'))

core = Node()
core.add_sender(new_sender(ADDRESS_CM), ADDRESS_CM)
core.send_message_to_address(ADDRESS_CM, iv)
core.send_message_to_address(ADDRESS_CM, encrypted_symmetric_key)
core.send_message_to_address(ADDRESS_CM, ciphertext)
core.close_connection(ADDRESS_CM)
#
# core.add_listener(new_listener(ADDRESS_MC), ADDRESS_MC)
# core.accept_connection(ADDRESS_MC)
# print(core.receive_message(ADDRESS_MC))
# core.close_connection(ADDRESS_MC)
