Set of scripts for playing with LoRaWAN

**generate_keys.py** to generate RSA key pairs that will can be used for encrypting/decrypting LoRaWAN messages. Or any strings in general.

**message.py** contains functions for encrypting/decrypting data (LoRaWAN messages). It uses RSA asymetric encryption on the AES key that
has been used for encrypting/decrypting the message data. This is common workaround, because RSA (PKCS1_XXX) can only encrypt/decrypt
a limited size strings. There is also a signature mechanism in place to make sure the message really comes from the specific sender.
