import string
import random
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from Crypto.Cipher import DES, Blowfish
from Crypto.Util.Padding import pad, unpad

# Glodal variables
text:str = input("Enter text: ").upper()

def CaesarEncrypt(text, shift) -> str:
    alphabet: str = string.ascii_uppercase
    encrypted_text: str = ""
    for char in text:
        if char in alphabet:
            encrypted_text += alphabet[(alphabet.index(char) + shift) % 26]
        else:
            encrypted_text += char
    return encrypted_text

def CaesarDecrypt(text, shift) -> str:
    return CaesarEncrypt(text, -shift)

def generate_full_key(message, key) -> str:
    key: list = list(key)
    if len(message) == len(key):
        return key
    else:
        for i in range(len(message) - len(key)):
            key.append(key[i % len(key)])
    return ''.join(key)

def vigenere_encrypt(message, key) -> str:
    alphabet: str = string.ascii_uppercase
    message: str = message.upper()
    key: str = generate_full_key(message, key.upper())
    encrypted_message: list = []

    for i in range(len(message)):
        if message[i] in alphabet:
            message_index: str = alphabet.index(message[i])
            key_index: str = alphabet.index(key[i])
            encrypted_char: str = alphabet[(message_index + key_index) % len(alphabet)]
            encrypted_message.append(encrypted_char)
        else:
            encrypted_message.append(message[i])

    return ''.join(encrypted_message)

def vigenere_decrypt(encrypted_message, key):
    alphabet: str = string.ascii_uppercase
    encrypted_message: str = encrypted_message.upper()
    key: str = generate_full_key(encrypted_message, key.upper())
    decrypted_message: list = []

    for i in range(len(encrypted_message)):
        if encrypted_message[i] in alphabet:
            encrypted_index: str = alphabet.index(encrypted_message[i])
            key_index: str = alphabet.index(key[i])
            decrypted_char: str = alphabet[(encrypted_index - key_index) % len(alphabet)]
            decrypted_message.append(decrypted_char)
        else:
            decrypted_message.append(encrypted_message[i])

    return ''.join(decrypted_message)

# RSA
def generate_rsa_keys():
    private_key: str = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    return private_key, public_key

def rsa_encrypt(public_key, message):
    if isinstance(message, str):
        message = message.encode()
    encrypted_message = public_key.encrypt(
        message,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    return encrypted_message

def rsa_decrypt(private_key, encrypted_message):
    decrypted_message = private_key.decrypt(
        encrypted_message,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    return decrypted_message.decode()

# DES
def create_des_cipher(key):
    if len(key) != 8:
        raise ValueError("DES key must be exactly 8 bytes long")
    cipher = DES.new(key, DES.MODE_CBC)
    return cipher

def des_encrypt(cipher, plaintext):
    plaintext = pad(plaintext.encode(), DES.block_size) 
    ciphertext = cipher.encrypt(plaintext)
    return ciphertext, cipher.iv

def des_decrypt(key, ciphertext, iv):
    cipher = DES.new(key, DES.MODE_CBC, iv=iv)
    decrypted_message = unpad(cipher.decrypt(ciphertext), DES.block_size)
    return decrypted_message.decode()  
