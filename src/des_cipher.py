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


# Prompt IA: Generame un bloque main para probar las funciones que he hecho en este archivo, para ver si todo funciona bien
    
if __name__ == "__main__":
    key = generate_des_key()
    des_text = (
        "The DES block cipher is a 16-round Feistel network with a block length of "
        "64 bits and a key length of 56 bits. The same round function f is used "
        "in each of the 16 rounds. The round function takes a 48-bit sub-key and, as "
        "expected for a (balanced) Feistel network, a 32-bit input (namely, half a block). "
        "The key schedule of DES is used to derive a sequence of 48-bit sub-keys k1, "
        "... , k16 from the 56-bit master key."
    ).encode("utf-8")

    ciphertext = encrypt_des_ecb(des_text, key)
    recovered = decrypt_des_ecb(ciphertext, key)

    print("=== Prueba DES-ECB con texto del laboratorio ===")
    print(f"Longitud plaintext: {len(des_text)} bytes")
    print(f"Longitud ciphertext: {len(ciphertext)} bytes")
    print(f"Ciphertext (hex, primeros 64): {ciphertext.hex()[:64]}...")
    print(f"Coincide: {recovered == des_text}")
    print("-" * 40)

    # prueba de error esperado (ciphertext invalido)
    try:
        decrypt_des_ecb(b"12345", key)
    except ValueError as e:
        print(f"Error esperado en decrypt: {e}")