from Crypto.PublicKey import RSA

from os import path


def generate_paths(node_name):
    private_key_path = "keys/" + node_name + "_private_key.pem"
    public_key_path = "keys/" + node_name + "_public_key.pem"

    return private_key_path, public_key_path


def generate_keys(node_name):
    private_key_path, public_key_path = generate_paths(node_name)

    if not path.exists(private_key_path):
        private_key = RSA.generate(1024)
        f = open(private_key_path, 'wb')
        f.write(private_key.export_key('PEM'))
        f.close()

    if not path.exists(public_key_path):
        f = open(private_key_path, 'r')
        private_key = RSA.import_key(f.read())
        public_key = private_key.publickey()
        f = open(public_key_path, 'wb')
        f.write(public_key.export_key('PEM'))
        f.close()

    private_key = load_private_keys(node_name)
    public_key = load_public_keys(node_name)

    return private_key, public_key


def load_private_keys(node_name):
    private_key_path, public_key_path = generate_paths(node_name)
    f = open(private_key_path, 'r')
    private_key = f.read()
    f.close()

    return private_key


def load_public_keys(node_name):
    private_key_path, public_key_path = generate_paths(node_name)
    f = open(public_key_path, 'r')
    public_key = f.read()
    f.close()

    return public_key
