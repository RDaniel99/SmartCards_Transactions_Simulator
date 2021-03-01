from tinydb import TinyDB, Query

bank_deposit = TinyDB("back_deposit.json")

User = Query()


def insert():
    bank_deposit.insert({'card_number': '310119989',
                         'card_exp': '01/02',
                         'ccode': '456',
                         'amount': '9000'})

    bank_deposit.insert({'card_number': '123456789',
                         'card_exp': '03/02',
                         'ccode': '456',
                         'amount': '100000'})
    bank_deposit.insert({'card_number': '270119999',
                         'card_exp': '04/02',
                         'ccode': '496',
                         'amount': '100'})


def search(card_number):
    results = bank_deposit.search(User.card_number == card_number)
    return results


def update(amount, card_number):
    bank_deposit.update({'amount': amount}, User.card_number == card_number)
