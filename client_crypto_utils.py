from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

def msg_encrypt(plaintext_msg, key):
    encrypted_msg = key.encrypt(
    plaintext_msg.encode(),
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA512()),
        algorithm=hashes.SHA512(),
        label=None))
    return encrypted_msg

def msg_decrypt(encrypted_msg, key):
    plaintext_msg = key.decrypt(
    encrypted_msg,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA512()),
        algorithm=hashes.SHA512(),
        label=None))
    return plaintext_msg.decode()
