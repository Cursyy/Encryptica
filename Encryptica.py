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

