import json

from node import Node
from node import new_sender
from node import new_listener
from constants import ADDRESS_MC
from constants import ADDRESS_CM
from constants import ADDRESS_MPG
from Crypto.Random import get_random_bytes
import crypto_utils as crypto_utils
import keys_utils as keys_utils

merchant_private_key = keys_utils.load_private_keys("merchant")

# STEP 1 - Receive {PubKC}PubKM
# BEGIN
core = Node()

core.add_listener(new_listener(ADDRESS_CM), ADDRESS_CM)
core.accept_connection(ADDRESS_CM)
iv = core.receive_message(ADDRESS_CM)
encrypted_symmetric_key = core.receive_message(ADDRESS_CM)
ciphertext = core.receive_message(ADDRESS_CM)
core.close_connection(ADDRESS_CM)

symmetric_session_key = crypto_utils.decrypt_rsa(merchant_private_key, encrypted_symmetric_key)
client_public_key = crypto_utils.decrypt_aes(symmetric_session_key, ciphertext, iv)
# END

# STEP 2 - Send {Sid, SigM(Sid)}PubKC
# BEGIN
sid, signed_hash = crypto_utils.get_signature(get_random_bytes(8), merchant_private_key)

messages = [bytes(sid, encoding='utf-8'), bytes(signed_hash, encoding='utf-8')]

encrypted_messages = crypto_utils.hybrid_encryption(messages, client_public_key)

for encrypted_message in encrypted_messages:
    del(encrypted_message[2])
    # we delete symmetric key, no need to send, but we need it for checking purposes

core.add_sender(new_sender(ADDRESS_MC), ADDRESS_MC)
core.send_message_to_address(ADDRESS_MC, encrypted_messages)
core.close_connection(ADDRESS_MC)
# END

# STEP 3 - Receive {PM, PO}PubKM
# BEGIN

core.add_listener(new_listener(ADDRESS_CM), ADDRESS_CM)
core.accept_connection(ADDRESS_CM)

encrypted_symmetric_key = core.receive_message(ADDRESS_CM)
ciphertext = core.receive_message(ADDRESS_CM)
iv = core.receive_message(ADDRESS_CM)

encrypted_symmetric_key_2 = core.receive_message(ADDRESS_CM)
ciphertext_2 = core.receive_message(ADDRESS_CM)
iv_2 = core.receive_message(ADDRESS_CM)

core.close_connection(ADDRESS_CM)

# END

# STEP 4 - Send {PM, SigM(Sid, PubKC, Amount)}PubKPG to PG
# BEGIN

K = crypto_utils.decrypt_rsa(merchant_private_key, encrypted_symmetric_key)
K_2 = crypto_utils.decrypt_rsa(merchant_private_key, encrypted_symmetric_key_2)
PM = json.loads(crypto_utils.decrypt_aes(K, ciphertext, iv))
PO = json.loads(crypto_utils.decrypt_aes(K_2, ciphertext_2, iv_2))

sig_dict_for_step_4 = dict()
sig_dict_for_step_4["amount"] = PO["amount"]
sig_dict_for_step_4["sid"] = sid
sig_dict_for_step_4["pubKC"] = client_public_key

signature_for_step_4 = crypto_utils.get_signature(json.dumps(sig_dict_for_step_4).encode('utf-8'), merchant_private_key)

payment_gateway_public_key = keys_utils.load_public_keys("payment_gateway")

encrypted_symmetric_key, ciphertext, _, iv = crypto_utils.hybrid_encryption_individual(json.dumps(PM).encode('utf-8'), payment_gateway_public_key)
encrypted_symmetric_key_2, ciphertext_2, _, iv_2 = crypto_utils.hybrid_encryption_individual(json.dumps(sig_dict_for_step_4).encode('utf-8'), payment_gateway_public_key)

core.add_sender(new_sender(ADDRESS_MPG), ADDRESS_MPG)

core.send_message_to_address(ADDRESS_MPG, encrypted_symmetric_key)
core.send_message_to_address(ADDRESS_MPG, ciphertext)
core.send_message_to_address(ADDRESS_MPG, iv)

core.send_message_to_address(ADDRESS_MPG, encrypted_symmetric_key_2)
core.send_message_to_address(ADDRESS_MPG, ciphertext_2)
core.send_message_to_address(ADDRESS_MPG, iv_2)

core.close_connection(ADDRESS_MPG)

# END

# M = json.loads(dict)

# K = crypto_utils.decrypt_rsa(payment_gateway_private_key, base64.b64decode(M["PI"]["K"]))
# M = crypto_utils.decrypt_aes(K, base64.b64decode(M["PI"]["M"]), base64.b64decode(M["PI"]["IV"]))
#
# print(M)
# M = json.loads(dict)
#
# K = crypto_utils.decrypt_rsa(payment_gateway_private_key, base64.b64decode(M["SigC(PI)"]["K"]))
# M = crypto_utils.decrypt_aes(K, base64.b64decode(M["SigC(PI)"]["M"]), base64.b64decode(M["SigC(PI)"]["IV"]))
#
# print(M)

# END
