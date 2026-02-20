"""
Generador de claves criptográficamente seguras.
"""
import secrets


def generate_des_key():
    """
    Genera una clave DES aleatoria de 8 bytes (64 bits).
    
    Nota: DES usa efectivamente 56 bits (los otros 8 son de paridad),
    pero la clave es de 8 bytes.

    """

    token = secrets.token_bytes(8)

    return token


def generate_3des_key(key_option: int = 2):
    """
    Genera una clave 3DES aleatoria.   

    """

    if key_option == 2:
        return secrets.token_bytes(16)
    elif key_option == 3:
        return secrets.token_bytes(24)
    else:
        raise ValueError("key_option debe ser 2 o 3")


def generate_aes_key(key_size: int = 256):
    """
    Genera una clave AES aleatoria.
    
   
    """
    # Convertir bits a bytes: key_size // 8

    if key_size not in {128,192,256}:
        raise ValueError("key_size debe ser 128, 192 o 256")
    
    num_bytes = key_size // 8

    return secrets.token_bytes(num_bytes)


def generate_iv(block_size: int = 8) -> bytes:
    """
    Genera un vector de inicialización (IV) aleatorio.

    """

    if block_size <= 0:
        raise ValueError("block_size debe ser mayor a 0")
    
    return secrets.token_bytes(block_size)