from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from PIL import Image
from pathlib import Path

def png_to_ppm(input_png: str, output_ppm: str) -> None:

    with Image.open(input_png) as img:

        img_rgb = img.convert("RGB")

        img_rgb.save(output_ppm, format="PPM")

# Prompt: Dame una funcion que lea las fotos ppm
def read_ppm_header_and_pixels(ppm_path: str) -> tuple[bytes, bytes]:
    """
    Lee un archivo PPM (P6), valida header y retorna:
    (header_bytes, pixel_bytes)
    """
    data = Path(ppm_path).read_bytes()
    if not data:
        raise ValueError("El archivo PPM esta vacio")

    i = 0
    n = len(data)

    def skip_ws_and_comments(idx: int) -> int:
        while idx < n:
            b = data[idx]
            if b in b" \t\r\n":
                idx += 1
                continue
            if b == ord("#"):
                # Saltar comentario hasta fin de linea
                idx += 1
                while idx < n and data[idx] not in b"\r\n":
                    idx += 1
                continue
            break
        return idx

    def read_token(idx: int) -> tuple[bytes, int]:
        idx = skip_ws_and_comments(idx)
        start = idx
        while idx < n and data[idx] not in b" \t\r\n#":
            idx += 1
        if start == idx:
            raise ValueError("Header PPM invalido")
        return data[start:idx], idx

    magic, i = read_token(i)
    if magic != b"P6":
        raise ValueError("Formato no soportado: se esperaba P6")

    width_tok, i = read_token(i)
    height_tok, i = read_token(i)
    maxval_tok, i = read_token(i)

    try:
        width = int(width_tok)
        height = int(height_tok)
        maxval = int(maxval_tok)
    except ValueError as e:
        raise ValueError("Dimensiones o maxval invalidos en header PPM") from e

    if width <= 0 or height <= 0:
        raise ValueError("Dimensiones invalidas en PPM")
    if maxval != 255:
        raise ValueError("Solo se soporta PPM con maxval=255")

    pixel_len = width * height * 3
    if pixel_len > len(data):
        raise ValueError("Archivo PPM corrupto (tamano insuficiente)")

    # Para no ambiguedad con bytes de pixel que parecen whitespace,
    # se toma el raster desde el final.
    header_end = len(data) - pixel_len
    if header_end <= 0:
        raise ValueError("Header PPM invalido")

    header_bytes = data[:header_end]
    pixel_bytes = data[header_end:]

    if len(pixel_bytes) != pixel_len:
        raise ValueError("Tamano de pixeles inconsistente")

    return header_bytes, pixel_bytes




def encrypt_ecb(pixel_data: bytes, key: bytes) -> bytes:

    if type(pixel_data) is not bytes:

        raise TypeError("pixel_data debe ser bytes")
    
    if type(key) is not bytes:

        raise TypeError("key debe ser bytes")

    if len(key) != 32:
        raise ValueError("key debe tener 32 bytes")

    cipher = AES.new(key, AES.MODE_ECB)

    padded = pad(pixel_data, 16)

    encrypted = cipher.encrypt(padded)

    return encrypted[0:len(pixel_data)]



def encrypt_cbc(pixel_data: bytes, key: bytes, iv: bytes) -> bytes:

    if type(pixel_data) is not bytes:

        raise TypeError("pixel_data debe ser bytes")
    
    if type(key) is not bytes:

        raise TypeError("key debe ser bytes")
    
    if type(iv) is not bytes:

        raise TypeError("iv debe ser bytes")

    if len(key) != 32:
        raise ValueError("key debe tener 32 bytes")
    
    if len(iv) != 16:
        raise ValueError("iv debe tener 16 bytes")

    cipher = AES.new(key, AES.MODE_CBC, iv=iv)

    padded = pad(pixel_data, 16)

    encrypted = cipher.encrypt(padded)

    return encrypted[0:len(pixel_data)]




def encrypt_ctr(pixel_data: bytes, key: bytes, nonce: bytes) -> bytes:

    if type(pixel_data) is not bytes:

        raise TypeError("pixel_data debe ser bytes")
    
    if type(key) is not bytes:

        raise TypeError("key debe ser bytes")
    
    if type(nonce) is not bytes:

        raise TypeError("nonce debe ser bytes")
    
    if len(key) != 32:
        raise ValueError("key debe tener 32 bytes")
    
    if len(nonce) != 8:
        raise ValueError("nonce debe tener 8 bytes")

    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)

    return cipher.encrypt(pixel_data)




def write_ppm(output_path: str, header: bytes, pixel_data: bytes) -> None:

    if type(header) is not bytes:

        raise TypeError("header debe ser bytes")
    
    if type(pixel_data) is not bytes:

        raise TypeError("pixel_data debe ser bytes")

    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    Path(output_path).write_bytes(header + pixel_data)
