from Cryptodome.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import base64


def decrypt_aes(key, msg, iv):
    """Method to decrypt using AES (same IV as encryption)"""
    cipher = AES.new(key, AES.MODE_CFB, iv)
    plaintext = cipher.decrypt(msg)
    return plaintext.decode('utf-8')


def decrypt_rsa(key, ciphertext):
    """Method use to encrypt using RSA"""
    key = RSA.importKey(key)
    cipher = PKCS1_OAEP.new(key)
    return cipher.decrypt(ciphertext)


def hybrid_encryption(messages, digital_envelope):
    encrypted_messages = []
    for message in messages:
        encrypted_symmetric_key, encrypted_message, symmetric_session_key, iv = hybrid_encryption_individual(message,
                                                                                                             digital_envelope)
        encrypted_messages.append([encrypted_symmetric_key, encrypted_message, symmetric_session_key, iv])

    return encrypted_messages


def hybrid_encryption_individual(message, digital_envelope):
    symmetric_session_key = get_random_bytes(32)
    iv = get_random_bytes(16)

    cipher_asymmetric = PKCS1_OAEP.new(RSA.import_key(digital_envelope))
    encrypted_symmetric_key = cipher_asymmetric.encrypt(symmetric_session_key)

    cipher_symmetric = AES.new(symmetric_session_key, AES.MODE_CFB, iv)

    encrypted_message = cipher_symmetric.encrypt(message)

    return encrypted_symmetric_key, encrypted_message, symmetric_session_key, iv


def get_signature(arg, private_key):
    sid_hash = SHA256.new(arg)
    key = RSA.import_key(private_key)

    signature = pkcs1_15.new(key).sign(sid_hash)

    return base64.b64encode(arg).decode(), base64.b64encode(signature).decode()
