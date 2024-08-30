import string
import random

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
