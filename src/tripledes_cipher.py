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

    tripledes_text = (
        "The main weakness of DES is its short key. It thus makes sense to try to "
        "design a block cipher with a larger key length using DES as a building block. "
        "Some approaches to doing so are discussed in this section. Although we refer "
        "to DES frequently throughout the discussion, and DES is the most prominent "
        "block cipher to which these techniques have been applied, everything we say "
        "here applies generically to any block cipher."
    ).encode("utf-8")

    print("=== Prueba 3DES-CBC con clave de 16 bytes (2-key) ===")
    key_2k = generate_3des_key(2)
    iv_2k = generate_iv(8)  # IV nuevo por mensaje
    ct_2k = encrypt_3des_cbc(tripledes_text, key_2k, iv_2k)
    pt_2k = decrypt_3des_cbc(ct_2k, key_2k, iv_2k)
    print(f"Longitud plaintext: {len(tripledes_text)} bytes")
    print(f"Longitud ciphertext: {len(ct_2k)} bytes")
    print(f"IV (hex): {iv_2k.hex()}")
    print(f"Ciphertext (hex, primeros 64): {ct_2k.hex()[:64]}...")
    print(f"Coincide: {pt_2k == tripledes_text}")
    print("-" * 50)

    print("\n=== Prueba 3DES-CBC con clave de 24 bytes (3-key) ===")
    key_3k = generate_3des_key(3)
    iv_3k = generate_iv(8)  # IV nuevo por mensaje
    ct_3k = encrypt_3des_cbc(tripledes_text, key_3k, iv_3k)
    pt_3k = decrypt_3des_cbc(ct_3k, key_3k, iv_3k)
    print(f"Longitud plaintext: {len(tripledes_text)} bytes")
    print(f"Longitud ciphertext: {len(ct_3k)} bytes")
    print(f"IV (hex): {iv_3k.hex()}")
    print(f"Ciphertext (hex, primeros 64): {ct_3k.hex()[:64]}...")
    print(f"Coincide: {pt_3k == tripledes_text}")
    print("-" * 50)

    # Caso de error esperado: ciphertext no multiplo de 8
    try:
        iv = generate_iv(8)
        decrypt_3des_cbc(b"12345", key_2k, iv)
    except ValueError as e:
        print(f"\nError esperado en decrypt: {e}")
