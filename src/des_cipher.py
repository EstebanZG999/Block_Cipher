from Crypto.Cipher import DES
from src.utils import pkcs7_pad, pkcs7_unpad

def encrypt_des_ecb(plaintext, key):

    if type(plaintext) is not bytes:
        raise TypeError("plaintext debe ser bytes")
    
    if type(key) is not bytes:
        raise TypeError("key debe ser bytes")
    
    if len(key) != 8:
        raise ValueError("key debe tener 8 bytes")
    
    padded = pkcs7_pad(plaintext, 8)
    cipher = DES.new(key, DES.MODE_ECB)

    return cipher.encrypt(padded)
    
def decrypt_des_ecb(ciphertext, key):

    if type(ciphertext) is not bytes:
        raise TypeError("ciphertext debe ser bytes")
    
    if type(key) is not bytes:
        raise TypeError("key debe ser bytes")
    
    if len(key) != 8:
        raise ValueError("key debe tener 8 bytes")
    
    if len(ciphertext) == 0 or len(ciphertext) % 8 != 0:
        raise ValueError("ciphertext debe ser no vacio y multiplo de 8")
    
    cipher = DES.new(key, DES.MODE_ECB)
    
    padded_plain = cipher.decrypt(ciphertext)

    return pkcs7_unpad(padded_plain)
