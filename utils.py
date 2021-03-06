import json
import string
import random
import crypto_utils as crypto_utils


def get_random_string(length):
    letters = string.digits
    result_str = ''.join(random.choice(letters) for i in range(length))

    return result_str


def generate_transaction_info(sid_and_signature, client_public_key, client_private_key):
    PI = dict()
    PI["card_number"] = '123456789'
    PI["card_exp"] = '03/02'
    PI["ccode"] = '456'
    PI["sid"] = sid_and_signature[0]
    PI["amount"] = '1000'
    PI["pubKC"] = client_public_key
    PI["nc"] = get_random_string(5)
    PI["m"] = "Emag"

    PO = dict()
    PO["orderdesc"] = "Pay the electricity bill"
    PO["sid"] = sid_and_signature[0]
    PO["amount"] = PI["amount"]
    PO["nc"] = PI["nc"]
    PO_signature_args = json.dumps(PO).encode('utf-8')

    PO["sigc(orderdesc, sid, amount, nc)"] = crypto_utils.get_signature(PO_signature_args, client_private_key)

    return PI, PO, PO_signature_args
