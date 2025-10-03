#!/usr/bin/env python3
# Description: Encrypt and sign a message using RSA and AES encryption
#
# Author: Jiri Popek
# Date: 2024-06-20
#
# Requirements: pycryptodome

from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
import base64

data = "I met aliens in UFO. Here is the map.".encode("utf-8")

KEY_LENGTH = 16

"""
Encrypt a message that is sent from sender to receiver
"""
def encrypt(sender, receiver, message):

    sender_private_key_name = "private_" + sender + ".pem"
    print(f"Loading '{sender_private_key_name}' to sign message")
    try:
        sign_key = RSA.import_key(open(sender_private_key_name).read())
    except Exception as e:
        print(f"Can not find '{sender} private key {sender_private_key_name}. {str(e)}")
        return None

    # encrypt with the recipient's public key
    receiver_public_key_name = "public_" + receiver + ".pem"
    print(f"Loading '{receiver_public_key_name}' to encrypt message for '{receiver}'")
    try:
        receiver_public_key = RSA.import_key(open(receiver_public_key_name).read())
    except Exception as e:
        print(f"Can not find {receiver}'s public key {receiver_public_key_name}. {str(e)}")
        return None

    session_key = get_random_bytes(KEY_LENGTH)

    # Encrypt the session key with the public RSA key
    cipher_rsa = PKCS1_OAEP.new(receiver_public_key)
    enc_session_key = cipher_rsa.encrypt(session_key)

    # Encrypt the message with the AES session key
    cipher_aes = AES.new(session_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(message)

    # Sign the encrypted message
    signature = pkcs1_15.new(sign_key).sign(SHA256.new(ciphertext))
    print(f"Signature length: {len(signature)} bytes")
    assert len(signature) == sign_key.size_in_bytes()


    assert len(cipher_aes.nonce) == KEY_LENGTH
    encrypted_msg = enc_session_key + cipher_aes.nonce + tag + signature + ciphertext

    return encrypted_msg

"""
Decrypt a message that has been sent from sender to receiver
"""
def decrypt(sender, receiver, encrypted_msg):
    receiver_private_key_name = "private_" + receiver + ".pem"
    print(f"Loading '{receiver_private_key_name}' to decrypt message from '{sender}'")
    try:
        receiver_private_key = RSA.import_key(open(receiver_private_key_name).read())
    except Exception as e:
        print(f"Can not find '{receiver} private key {receiver_private_key_name}. {str(e)}")
        return None

    # The receiver has the private RSA key. They will use it to decrypt the session key first, and with that the rest of the file
    spks = receiver_private_key.size_in_bytes()
    enc_session_key = encrypted_msg[:spks]
    nonce = encrypted_msg[spks:spks+KEY_LENGTH]
    tag = encrypted_msg[spks+KEY_LENGTH:spks+2*KEY_LENGTH]
    signature = encrypted_msg[spks+2*KEY_LENGTH:spks+2*KEY_LENGTH+256]
    ciphertext = encrypted_msg[spks+2*KEY_LENGTH+256:]

    # Decrypt the session key with the private RSA key
    cipher_rsa = PKCS1_OAEP.new(receiver_private_key)
    session_key = cipher_rsa.decrypt(enc_session_key)

    # Decrypt the message with the AES session key
    cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
    decrypted_msg = cipher_aes.decrypt_and_verify(ciphertext, tag)

    # Verify the signature with the sender's public key
    # The receiver needs to have the sender's public key
    # In a real application, the public key should be obtained from a trusted source
    # Here we assume the receiver already has the sender's public key
    sender_public_key_name = "public_" + sender + ".pem"
    print(f"Loading '{sender_public_key_name}' to verify message from '{sender}'")
    try:
        sender_public_key = RSA.import_key(open(sender_public_key_name).read())
    except Exception as e:
        print(f"Can not find '{sender}'s public key {sender_public_key_name}. {str(e)}")
        return None
    
    try:
        pkcs1_15.new(sender_public_key).verify(SHA256.new(ciphertext), signature)
        print("The signature is valid.")
    except (ValueError, TypeError):
        print("The signature is not valid.")
        return None

    return decrypted_msg


if __name__ == "__main__":
    # I am sending a message to Alex
    encrypted_msg = encrypt("me", "alex", data)
    print("Encrypted message:", base64.b64encode(encrypted_msg).decode("utf-8"))

    # Alex is receiving the message from me
    decrypted_msg = decrypt("me", "alex", encrypted_msg)
    print("Decrypted message:", decrypted_msg)

