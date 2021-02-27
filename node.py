from multiprocessing.connection import Client
from multiprocessing.connection import Listener


def new_listener(address, auth_key=bytes('0101001', 'utf-8')):
    return Listener(address, authkey=auth_key)


def new_sender(address, auth_key=bytes('0101001', 'utf-8')):
    return Client(address, authkey=auth_key)


class Node:
    def __init__(self):
        self.listeners = []
        self.addresses_listeners = []

        self.senders = []
        self.addresses_senders = []

    def add_listener(self, listener, address):
        self.listeners.append(listener)
        self.addresses_listeners.append(address)

    def add_sender(self, sender, address):
        self.senders.append(sender)
        self.addresses_senders.append(address)

    def send_message_to_address(self, address, message):
        # No error handling, use the correct addresses
        position = self.addresses_senders.index(address)

        self.senders[position].send(message)

    def close_connection(self, address):
        try:
            position = self.addresses_senders.index(address)

            self.senders[position].close()
            self.senders.pop(position)
            self.addresses_senders.pop(position)
        except:
            position = self.addresses_listeners.index(address)

            self.listeners[position].close()
            self.listeners.pop(position)
            self.addresses_listeners.pop(position)

    def accept_connection(self, address):
        # No error handling, use the correct addresses
        position = self.addresses_listeners.index(address)

        self.listeners[position] = self.listeners[position].accept()

    def receive_message(self, address):
        # No error handling, use the correct addresses
        position = self.addresses_listeners.index(address)

        return self.listeners[position].recv()
