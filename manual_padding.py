"""
Módulo de padding PKCS#7 para cifrados de bloque.
Implementación manual sin usar bibliotecas externas.
"""

def pkcs7_pad(data: bytes, block_size: int = 8)-> bytes:
    """
    Implementa padding PKCS#7 según RFC 5652.
    
    Regla: Si faltan N bytes para completar el bloque,
    agregar N bytes, cada uno con el valor N (recuerden seguir la regla de pkcs#7).
    
    Importante: Si el mensaje es múltiplo exacto del tamaño
    de bloque, se agrega un bloque completo de padding.
    
    Examples:
        >>> pkcs7_pad(b"HOLA", 8).hex()
        '484f4c4104040404'  # HOLA + 4 bytes con valor 0x04
        
        >>> pkcs7_pad(b"12345678", 8).hex()  # Exactamente 8 bytes
        '31323334353637380808080808080808'  # + bloque completo
    """
    if not (1 <= block_size <= 255):
        raise ValueError("El tamano del block size no es correcto")     

    pad_len = block_size - (len(data) % block_size)

    if pad_len == 0:
        pad_len = block_size
    
    padding = bytes([pad_len]) * pad_len


    return data + padding


def pkcs7_unpad(data: bytes) -> bytes:
    """
    Elimina padding PKCS#7 de los datos.
    
    Examples:
        >>> padded = pkcs7_pad(b"HOLA", 8)
        >>> pkcs7_unpad(padded)
        b'HOLA'
    """

    if not data:
        raise ValueError("Data tiene que tener")
    
    N = data[-1]

    if N < 1 or N > len(data):
        raise ValueError
    
    esperado = bytes([N]) * N

    if data[-N:] != esperado:
        raise ValueError

    return data[:-N]