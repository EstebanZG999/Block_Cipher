from Crypto.Cipher import DES
from src.utils import pkcs7_pad, pkcs7_unpad, generate_des_key

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


"Prompt IA: Generame un bloque main para probar las funciones que he hecho en este archivo, para ver si todo funciona bien"
    
if __name__ == "__main__":
    key = generate_des_key()
    mensajes = [
        b"Hola DES",   # no multiplo de 8
        b"12345678",   # multiplo exacto de 8
        b""            # vacio (PKCS#7 agrega bloque completo)
    ]

    for msg in mensajes:
        ciphertext = encrypt_des_ecb(msg, key)
        recovered = decrypt_des_ecb(ciphertext, key)

        print(f"Mensaje original: {msg}")
        print(f"Ciphertext (hex): {ciphertext.hex()}")
        print(f"Recuperado: {recovered}")
        print(f"Coincide: {recovered == msg}")
        print("-" * 40)

    # prueba de error esperado (ciphertext invalido)
    try:
        decrypt_des_ecb(b"12345", key)
    except ValueError as e:
        print(f"Error esperado en decrypt: {e}")