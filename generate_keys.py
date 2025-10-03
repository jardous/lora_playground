#!/usr/bin/env python3
# generates public key stored in receiver.pem and private key stored in private.pem.
# These files will be used in the examples below. Every time,
# it generates different public key and private key pair.
#
# https://pycryptodome.readthedocs.io/en/latest/src/examples.html#generate-an-rsa-key
#
import sys
import os.path
from Crypto.PublicKey import RSA

KEY_SIZE = 128

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 generate_keys.py <identifier>")
        sys.exit(1)

    private_filename = "private_" + sys.argv[1] + ".pem"
    public_filename = "public_" + sys.argv[1] + ".pem"
    if os.path.isfile(private_filename):
        print(f"{private_filename} already exists. Please remove it first.")
        sys.exit(1)
    if os.path.isfile(public_filename):
        print(f"{public_filename} already exists. Please remove it first.")
        sys.exit(1)

    key = RSA.generate(KEY_SIZE)
    private_key = key.export_key()
    with open(private_filename, "wb") as f:
        f.write(private_key)

    public_key = key.publickey().export_key()
    with open(public_filename, "wb") as f:
        f.write(public_key)

