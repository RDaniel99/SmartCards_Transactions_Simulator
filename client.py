import base64

from constants import ADDRESS_CM
from constants import ADDRESS_MC
import pickle
from node import Node
from node import new_listener
from node import new_sender
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import string
import utils as utils
import crypto_utils as crypto_utils
import keys_utils as keys_utils
import numpy as np
import json


payment_gateway_public_key = keys_utils.load_public_keys("payment_gateway")
merchant_public_key = keys_utils.load_public_keys("merchant")
merchant_private_key = keys_utils.load_private_keys("merchant")

client_public_key = keys_utils.load_public_keys("client")
client_private_key = keys_utils.load_private_keys("client")

# STEP 1 - Send {PubKC}PubKM
# BEGIN

# Hybrid encryption of a message m with the key k means that the message m is encrypted using a symmetric session key
# s, which is in turn encrypted using an asymmetric key k (the digital envelope).
encrypted_symmetric_key, encrypted_message, symmetric_session_key, iv = crypto_utils.hybrid_encryption_individual(
    bytes(client_public_key, encoding='utf-8'), bytes(merchant_public_key, encoding='utf-8'))

core = Node()
core.add_sender(new_sender(ADDRESS_CM), ADDRESS_CM)
core.send_message_to_address(ADDRESS_CM, iv)
core.send_message_to_address(ADDRESS_CM, encrypted_symmetric_key)
core.send_message_to_address(ADDRESS_CM, encrypted_message)
core.close_connection(ADDRESS_CM)
# END

# STEP 2 - Receive {Sid, SigM(Sid)}PubKC
# BEGIN
core.add_listener(new_listener(ADDRESS_MC), ADDRESS_MC)
core.accept_connection(ADDRESS_MC)
encrypted_messages = core.receive_message(ADDRESS_MC)
core.close_connection(ADDRESS_MC)

sid_and_signature = []
for encrypted_message in encrypted_messages:
    encrypted_symmetric_key, message, iv = encrypted_message
    K = crypto_utils.decrypt_rsa(client_private_key, encrypted_symmetric_key)
    m = crypto_utils.decrypt_aes(K, message, iv)

    sid_and_signature.append(m)
# END

# STEP 3 - Send {PM, PO}PubKM
# BEGIN
messages = utils.generate_transaction_info(sid_and_signature, client_public_key)

PI = messages
PI_bytes = json.dumps(PI).encode('utf-8')

_, signature = crypto_utils.get_signature(PI_bytes, client_private_key)

print(signature)
print(PI)

PM = (PI, signature)

PI_PM = [PI_bytes, bytes(signature, encoding='utf-8')]

payment_gateway_private_key = keys_utils.load_private_keys("payment_gateway")

encrypted_symmetric_key, ciphertext, _, iv = crypto_utils.hybrid_encryption_individual(PI_PM[0], payment_gateway_public_key)

PM_encypted = dict()
PM_encypted["PI"] = dict()
PM_encypted["PI"]["K"] = base64.b64encode(encrypted_symmetric_key).decode()
PM_encypted["PI"]["M"] = base64.b64encode(ciphertext).decode()
PM_encypted["PI"]["IV"] = base64.b64encode(iv).decode()

encrypted_symmetric_key, ciphertext, _, iv = crypto_utils.hybrid_encryption_individual(PI_PM[1], payment_gateway_public_key)

PM_encypted["SigC(PI)"] = dict()
PM_encypted["SigC(PI)"]["K"] = base64.b64encode(encrypted_symmetric_key).decode()
PM_encypted["SigC(PI)"]["M"] = base64.b64encode(ciphertext).decode()
PM_encypted["SigC(PI)"]["IV"] = base64.b64encode(iv).decode()

# print(base64.b64decode(PM_encypted["SigC(PI)"]["M"]))
# print(ciphertext)

PM_encypted_bytes = json.dumps(PM_encypted).encode('utf-8')

encrypted_symmetric_key, ciphertext, _, iv = crypto_utils.hybrid_encryption_individual(PM_encypted_bytes, merchant_public_key)

K = crypto_utils.decrypt_rsa(merchant_private_key, encrypted_symmetric_key)
dict = crypto_utils.decrypt_aes(K, ciphertext, iv)

M = json.loads(dict)

K = crypto_utils.decrypt_rsa(payment_gateway_private_key, base64.b64decode(M["PI"]["K"]))
M = crypto_utils.decrypt_aes(K, base64.b64decode(M["PI"]["M"]), base64.b64decode(M["PI"]["IV"]))

print(M)
M = json.loads(dict)

K = crypto_utils.decrypt_rsa(payment_gateway_private_key, base64.b64decode(M["SigC(PI)"]["K"]))
M = crypto_utils.decrypt_aes(K, base64.b64decode(M["SigC(PI)"]["M"]), base64.b64decode(M["SigC(PI)"]["IV"]))

print(M)

print(M)

