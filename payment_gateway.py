import json

from node import Node
from node import new_sender
from node import new_listener
from constants import ADDRESS_MPG
import keys_utils as keys_utils
import crypto_utils as crypto_utils

from os import path

payment_gateway_private_key = keys_utils.load_private_keys("payment_gateway")

core = Node()

# STEP 4 - Receive {PM, SigM(Sid, PubKC, Amount)}PubKPG
# BEGIN

core.add_listener(new_listener(ADDRESS_MPG), ADDRESS_MPG)
core.accept_connection(ADDRESS_MPG)

encrypted_symmetric_key = core.receive_message(ADDRESS_MPG)
ciphertext = core.receive_message(ADDRESS_MPG)
iv = core.receive_message(ADDRESS_MPG)

encrypted_symmetric_key_2 = core.receive_message(ADDRESS_MPG)
ciphertext_2 = core.receive_message(ADDRESS_MPG)
iv_2 = core.receive_message(ADDRESS_MPG)

core.close_connection(ADDRESS_MPG)

K = crypto_utils.decrypt_rsa(payment_gateway_private_key, encrypted_symmetric_key)
K_2 = crypto_utils.decrypt_rsa(payment_gateway_private_key, encrypted_symmetric_key_2)
PM = json.loads(crypto_utils.decrypt_aes(K, ciphertext, iv))
sigM = json.loads(crypto_utils.decrypt_aes(K_2, ciphertext_2, iv_2))

print(PM)
print(sigM)

# END