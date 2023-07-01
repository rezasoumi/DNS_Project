import socket
import threading
import json
import hmac
import os
import base64
from Crypto.Cipher import DES3, AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Protocol.KDF import PBKDF2
import hashlib
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization

def generate_pub_prv_key():
    password = input("Enter private key password: ")
  
    SERVER_PRIVATE_KEY = RSA.generate(11000)
    SERVER_PUBLIC_KEY = SERVER_PRIVATE_KEY.publickey()

    hashed_password = hashlib.sha256(password.encode()).digest()

    ciphered_private_key = SERVER_PRIVATE_KEY.export_key(passphrase=hashed_password, pkcs=8, protection="scryptAndAES128-CBC")

    with open("pourya_private_rsa.pem", "wb") as file:
        file.write(ciphered_private_key)

    with open("pourya_public_rsa.pem", "wb") as file:
        file.write(SERVER_PUBLIC_KEY.export_key())

def load_pub_prv_key():

    global SERVER_PRIVATE_KEY, SERVER_PUBLIC_KEY

    password = input("Enter private key password: ")
    hashed_password = hashlib.sha256(password.encode()).digest()
    
    with open("ali_private_rsa.pem", "rb") as file:
        encrypted_data = file.read()

    SERVER_PRIVATE_KEY = RSA.import_key(encrypted_data, passphrase=hashed_password)

    with open("ali_public_rsa.pem", "rb") as file:
        public_key = file.read()
        SERVER_PUBLIC_KEY = RSA.import_key(public_key)

generate_pub_prv_key()