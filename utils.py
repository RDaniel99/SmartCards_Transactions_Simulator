import string
import random
import utils as utils


def get_random_string(length):
    letters = string.digits
    result_str = ''.join(random.choice(letters) for i in range(length))

    return result_str


def generate_transaction_info(sid_and_signature, client_public_key):
    digits = string.digits
    card_number = utils.get_random_string(10)
    card_exp = utils.get_random_string(2) + "/" + utils.get_random_string(2)
    ccode = utils.get_random_string(3)
    amount = utils.get_random_string(4) + " euro"
    nc = utils.get_random_string(5)
    merchant_name = "Emag"

    messages = dict()
    messages["card_number"] = card_number
    messages["card_exp"] = card_exp
    messages["ccode"] = ccode
    messages["sid"] = sid_and_signature[0]
    messages["amount"] = amount
    messages["pubKC"] = client_public_key
    messages["nc"] = nc
    messages["m"] = merchant_name

    return messages
