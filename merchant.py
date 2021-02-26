from node import Node
from node import new_sender
from node import new_listener
from constants import ADDRESS_MC
from constants import ADDRESS_CM
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
