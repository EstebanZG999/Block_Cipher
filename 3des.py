
from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad


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