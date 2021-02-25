from node import Node
from node import new_sender
from node import new_listener
from constants import ADDRESS_MC
from constants import ADDRESS_CM
import utils as utils

utils.generate_keys(False)

core = Node()

core.add_listener(new_listener(ADDRESS_CM), ADDRESS_CM)
core.accept_connection(ADDRESS_CM)
iv = core.receive_message(ADDRESS_CM)
encrypted_symmetric_key = core.receive_message(ADDRESS_CM)
ciphertext = core.receive_message(ADDRESS_CM)
core.close_connection(ADDRESS_CM)

symmetric_session_key = utils.decrypt_rsa('keys/merchant_private_key.pem', encrypted_symmetric_key)
client_public_key = utils.decrypt_aes(symmetric_session_key, ciphertext, iv)

print("-------------")
print(client_public_key)

sid, signed_hash = utils.get_signature()

print(sid)
print(signed_hash)

messages = []
messages.append(sid)
messages.append(signed_hash)

encrypted_messages = utils.hybrid_encryption(messages, client_public_key)
print("------------- key")
print(encrypted_messages[0][2])
print("-------------")

print("------------- message")
print(encrypted_messages[0][1])

print("------------- iv")
print(encrypted_messages[0][3])

for encrypted_message in encrypted_messages:
    del(encrypted_message[2])

core.add_sender(new_sender(ADDRESS_MC), ADDRESS_MC)
core.send_message_to_address(ADDRESS_MC, encrypted_messages)
core.close_connection(ADDRESS_MC)
# print(utils.decrypt_aes(symmetric_session_key, ciphertext))

#
#
# core.close_connection(ADDRESS_MC)
