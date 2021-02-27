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

PI, PO = utils.generate_transaction_info(sid_and_signature, client_public_key, client_private_key)
PI_bytes = json.dumps(PI).encode('utf-8')

_, signature = crypto_utils.get_signature(PI_bytes, client_private_key)

PI_PM = [PI_bytes, bytes(signature, encoding='utf-8')]

encrypted_symmetric_key, ciphertext, _, iv = crypto_utils.hybrid_encryption_individual(PI_PM[0], payment_gateway_public_key)

PM_encrypted = dict()
PM_encrypted["PI"] = dict()
PM_encrypted["PI"]["K"] = base64.b64encode(encrypted_symmetric_key).decode()
PM_encrypted["PI"]["M"] = base64.b64encode(ciphertext).decode()
PM_encrypted["PI"]["IV"] = base64.b64encode(iv).decode()

encrypted_symmetric_key, ciphertext, _, iv = crypto_utils.hybrid_encryption_individual(PI_PM[1], payment_gateway_public_key)

PM_encrypted["SigC(PI)"] = dict()
PM_encrypted["SigC(PI)"]["K"] = base64.b64encode(encrypted_symmetric_key).decode()
PM_encrypted["SigC(PI)"]["M"] = base64.b64encode(ciphertext).decode()
PM_encrypted["SigC(PI)"]["IV"] = base64.b64encode(iv).decode()

# print(base64.b64decode(PM_encypted["SigC(PI)"]["M"]))
# print(ciphertext)

PM_encrypted_bytes = json.dumps(PM_encrypted).encode('utf-8')
PO_encrypted_bytes = json.dumps(PO).encode('utf-8')

encrypted_symmetric_key, ciphertext, _, iv = crypto_utils.hybrid_encryption_individual(PM_encrypted_bytes, merchant_public_key)
encrypted_symmetric_key_2, ciphertext_2, _, iv_2 = crypto_utils.hybrid_encryption_individual(PO_encrypted_bytes, merchant_public_key)

core.add_sender(new_sender(ADDRESS_CM), ADDRESS_CM)

core.send_message_to_address(ADDRESS_CM, encrypted_symmetric_key)
core.send_message_to_address(ADDRESS_CM, ciphertext)
core.send_message_to_address(ADDRESS_CM, iv)

core.send_message_to_address(ADDRESS_CM, encrypted_symmetric_key_2)
core.send_message_to_address(ADDRESS_CM, ciphertext_2)
core.send_message_to_address(ADDRESS_CM, iv_2)

core.close_connection(ADDRESS_CM)

# END

# STEP LAST
# BEGIN

core.add_listener(new_listener(ADDRESS_MC), ADDRESS_MC)
core.accept_connection(ADDRESS_MC)

encrypted_symmetric_key = core.receive_message(ADDRESS_MC)
ciphertext = core.receive_message(ADDRESS_MC)
iv = core.receive_message(ADDRESS_MC)

core.close_connection(ADDRESS_MC)

# END

K = crypto_utils.decrypt_rsa(client_private_key, encrypted_symmetric_key)
M = crypto_utils.decrypt_aes(K, ciphertext, iv)

print(M)
