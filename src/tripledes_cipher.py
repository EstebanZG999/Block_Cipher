from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad
from src.utils import generate_3des_key

def encrypt_3des_cbc(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    """    
    Example:
        >>> key = generate_3des_key(2)
        >>> iv = generate_iv(8)
        >>> plaintext = b"Mensaje secreto para 3DES"
        >>> ciphertext = encrypt_3des_cbc(plaintext, key, iv)
        >>> len(ciphertext) % 8
        0  # Debe ser múltiplo de 8 (tamaño de bloque de DES)
    """
    if not len(key) in {16, 24}:
        raise ValueError("key debe tener 16 o 24 bytes")
    
    if len(iv) != 8:
        raise ValueError("iv debe tener 8 bytes")
    
    cipher = DES3.new(key, DES3.MODE_CBC, iv=iv)

    padded = pad(plaintext, 8)

    return cipher.encrypt(padded)



def decrypt_3des_cbc(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    """    
    Example:
        >>> key = generate_3des_key(2)
        >>> iv = generate_iv(8)
        >>> plaintext = b"Mensaje secreto"
        >>> ciphertext = encrypt_3des_cbc(plaintext, key, iv)
        >>> decrypted = decrypt_3des_cbc(ciphertext, key, iv)
        >>> decrypted == plaintext
        True
    """
    if not len(key) in {16, 24}:
        raise ValueError("key debe tener 16 o 24 bytes")
    
    if len(iv) != 8:
        raise ValueError("iv debe tener 8 bytes")
    
    if len(ciphertext) % 8 != 0:
        raise ValueError("ciphertext debe ser múltiplo de 8")
    
    cipher = DES3.new(key, DES3.MODE_CBC, iv=iv)

    padded_plain = cipher.decrypt(ciphertext)

    return unpad(padded_plain, 8)



"Prompt IA: Generame un bloque main para probar las funciones que he hecho en este archivo, para ver si todo funciona bien"

if __name__ == "__main__":
    from src.utils import generate_3des_key, generate_iv

    mensajes = [
        b"Mensaje 3DES corto",
        b"12345678",  # multiplo exacto de 8
        b""           # vacio
    ]

    print("=== Prueba 3DES-CBC con clave de 16 bytes (2-key) ===")
    key_2k = generate_3des_key(2)

    for msg in mensajes:
        iv = generate_iv(8)  # IV nuevo por mensaje
        ct = encrypt_3des_cbc(msg, key_2k, iv)
        pt = decrypt_3des_cbc(ct, key_2k, iv)

        print(f"Mensaje original: {msg}")
        print(f"IV (hex): {iv.hex()}")
        print(f"Ciphertext (hex): {ct.hex()}")
        print(f"Recuperado: {pt}")
        print(f"Coincide: {pt == msg}")
        print("-" * 50)

    print("\n=== Prueba 3DES-CBC con clave de 24 bytes (3-key) ===")
    key_3k = generate_3des_key(3)

    for msg in mensajes:
        iv = generate_iv(8)  # IV nuevo por mensaje
        ct = encrypt_3des_cbc(msg, key_3k, iv)
        pt = decrypt_3des_cbc(ct, key_3k, iv)

        print(f"Mensaje original: {msg}")
        print(f"IV (hex): {iv.hex()}")
        print(f"Ciphertext (hex): {ct.hex()}")
        print(f"Recuperado: {pt}")
        print(f"Coincide: {pt == msg}")
        print("-" * 50)

    # Caso de error esperado: ciphertext no multiplo de 8
    try:
        iv = generate_iv(8)
        decrypt_3des_cbc(b"12345", key_2k, iv)
    except ValueError as e:
        print(f"\nError esperado en decrypt: {e}")