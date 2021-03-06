import base64
import json

from Cryptodome.Hash import SHA256

from node import Node
from node import new_sender
from node import new_listener
from constants import ADDRESS_MPG
from constants import ADDRESS_PGM
import keys_utils as keys_utils
import crypto_utils as crypto_utils
import bank_deposit

from os import path

payment_gateway_public_key = keys_utils.load_public_keys("payment_gateway")
payment_gateway_private_key = keys_utils.load_private_keys("payment_gateway")
client_public_key = keys_utils.load_public_keys("client")
merchant_private_key = keys_utils.load_private_keys("merchant")

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

# END

# STEP 5 - ..
# BEGIN
K = crypto_utils.decrypt_rsa(payment_gateway_private_key, encrypted_symmetric_key)
K_2 = crypto_utils.decrypt_rsa(payment_gateway_private_key, encrypted_symmetric_key_2)
PM = json.loads(crypto_utils.decrypt_aes(K, ciphertext, iv))
sigM = json.loads(crypto_utils.decrypt_aes(K_2, ciphertext_2, iv_2))

K_3 = crypto_utils.decrypt_rsa(payment_gateway_private_key, base64.b64decode(PM["PI"]["K"]))
M_3 = crypto_utils.decrypt_aes(K_3, base64.b64decode(PM["PI"]["M"]), base64.b64decode(PM["PI"]["IV"]))

K_sign = crypto_utils.decrypt_rsa(payment_gateway_private_key, base64.b64decode(PM["SigC(PI)"]["K"]))
M_sig = crypto_utils.decrypt_aes(K_sign, base64.b64decode(PM["SigC(PI)"]["M"]), base64.b64decode(PM["SigC(PI)"]["IV"]))

PI = json.loads(M_3)

sid = PI["sid"]
amount = PI["amount"]
nc = PI["nc"]
card_number = PI['card_number']
card_exp = PI['card_exp']
ccode = PI['ccode']

print("SigC(PI): ")
if (crypto_utils.verify_signature(client_public_key, M_sig, json.dumps(PI).encode('utf-8')) == False):
    exit(0)

resp = "404 Pg not found"

credit_card = bank_deposit.search(card_number, card_exp, ccode)
amount_available = 0
for r in credit_card:
    amount_available = r['amount']

if int(amount_available) - int(amount) < 0:
    resp = "The client does not have enough money to finish the tranzaction"
else:
    resp = "The transaction was successfully accomplished"
client_remaining_amount = int(amount_available) - int(amount)

mini_json = dict()
mini_json["resp"] = resp
mini_json["sid"] = sid
mini_json["amount"] = amount
mini_json["nc"] = nc

json_step_5 = dict()
json_step_5["resp"] = resp
json_step_5["sid"] = sid
json_step_5["sigPG"] = crypto_utils.get_signature(json.dumps(mini_json).encode("utf-8"), payment_gateway_private_key)[1]

merchant_public_key = keys_utils.load_public_keys("merchant")
encrypted_symmetric_key, ciphertext, _, iv = crypto_utils.hybrid_encryption_individual(
    json.dumps(json_step_5).encode("utf-8"), merchant_public_key)

sig_dict_for_step_4 = dict()
sig_dict_for_step_4["amount"] = amount
sig_dict_for_step_4["sid"] = sid
sig_dict_for_step_4["pubKC"] = client_public_key

# bank_deposit.insert()
print("SigM(Sid, PubKC, Amount):")
if (crypto_utils.verify_signature(merchant_public_key, base64.b64decode(sigM),
                                  json.dumps(sig_dict_for_step_4).encode('utf-8')) == True):

    if client_remaining_amount > 0:
        bank_deposit.update(str(client_remaining_amount), card_number)

        credit_card = bank_deposit.search('270119999', "04/02", "496")
        for r in credit_card:
            amount_available_merchant = r['amount']

        amount_remaining = int(amount_available_merchant) + int(amount)
        bank_deposit.update(str(amount_remaining), '270119999')

core.add_sender(new_sender(ADDRESS_PGM), ADDRESS_PGM)
core.send_message_to_address(ADDRESS_PGM, encrypted_symmetric_key)
core.send_message_to_address(ADDRESS_PGM, ciphertext)
core.send_message_to_address(ADDRESS_PGM, iv)
core.close_connection(ADDRESS_PGM)

# END
