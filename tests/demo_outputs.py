# Prompt: recopila todos los main en un archivo

from pathlib import Path

from Crypto.Cipher import AES, DES3
from Crypto.Util.Padding import pad
from PIL import Image

from src.aes_cipher import encrypt_cbc, encrypt_ecb, read_ppm_header_and_pixels, write_ppm
from src.des_cipher import decrypt_des_ecb, encrypt_des_ecb
from src.tripledes_cipher import decrypt_3des_cbc, encrypt_3des_cbc
from src.utils import (
    generate_3des_key,
    generate_aes_key,
    generate_des_key,
    generate_iv,
    pkcs7_pad,
    pkcs7_unpad,
)


DES_LAB_TEXT = (
    "The DES block cipher is a 16-round Feistel network with a block length of "
    "64 bits and a key length of 56 bits. The same round function f is used "
    "in each of the 16 rounds. The round function takes a 48-bit sub-key and, as "
    "expected for a (balanced) Feistel network, a 32-bit input (namely, half a block). "
    "The key schedule of DES is used to derive a sequence of 48-bit sub-keys k1, "
    "... , k16 from the 56-bit master key."
).encode("utf-8")

TRIPLEDES_LAB_TEXT = (
    "The main weakness of DES is its short key. It thus makes sense to try to "
    "design a block cipher with a larger key length using DES as a building block. "
    "Some approaches to doing so are discussed in this section. Although we refer "
    "to DES frequently throughout the discussion, and DES is the most prominent "
    "block cipher to which these techniques have been applied, everything we say "
    "here applies generically to any block cipher."
).encode("utf-8")


def _valid_3des_key(key_option: int) -> bytes:
    for _ in range(100):
        key = generate_3des_key(key_option)
        try:
            DES3.new(key, DES3.MODE_CBC, iv=b"\x00" * 8)
            return key
        except ValueError:
            continue
    raise RuntimeError("No se pudo generar una clave 3DES valida")


def _print_blocks(label: str, data: bytes, block_size: int = 16) -> None:
    print(label)
    for idx in range(0, len(data), block_size):
        block = data[idx : idx + block_size]
        print(f"  B{idx // block_size + 1}: {block.hex()}")


def demo_des() -> None:
    print("\n=== DES-ECB ===")
    key = generate_des_key()
    ciphertext = encrypt_des_ecb(DES_LAB_TEXT, key)
    recovered = decrypt_des_ecb(ciphertext, key)

    print(f"Longitud plaintext: {len(DES_LAB_TEXT)} bytes")
    print(f"Longitud ciphertext: {len(ciphertext)} bytes")
    print(f"Ciphertext (hex, primeros 64): {ciphertext.hex()[:64]}...")
    print(f"Coincide: {recovered == DES_LAB_TEXT}")

    try:
        decrypt_des_ecb(b"12345", key)
    except ValueError as exc:
        print(f"Error esperado en decrypt: {exc}")


def demo_3des() -> None:
    print("\n=== 3DES-CBC (16 y 24 bytes) ===")
    for key_option in (2, 3):
        key = _valid_3des_key(key_option)
        iv = generate_iv(8)
        ciphertext = encrypt_3des_cbc(TRIPLEDES_LAB_TEXT, key, iv)
        recovered = decrypt_3des_cbc(ciphertext, key, iv)

        print(f"\nkey_option={key_option} -> {len(key)} bytes")
        print(f"IV (hex): {iv.hex()}")
        print(f"Longitud plaintext: {len(TRIPLEDES_LAB_TEXT)} bytes")
        print(f"Longitud ciphertext: {len(ciphertext)} bytes")
        print(f"Ciphertext (hex, primeros 64): {ciphertext.hex()[:64]}...")
        print(f"Coincide: {recovered == TRIPLEDES_LAB_TEXT}")


def demo_aes_image() -> None:
    print("\n=== AES Imagen (ECB vs CBC) ===")
    ppm_input = Path("images/ejercicio_1.3/input/tux.ppm")
    ppm_ecb_out = Path("images/ejercicio_1.3/output/imagen_tux_ecb.ppm")
    ppm_cbc_out = Path("images/ejercicio_1.3/output/imagen_tux_cbc.ppm")
    png_ecb_out = Path("images/ejercicio_1.3/output/imagen_tux_ecb.png")
    png_cbc_out = Path("images/ejercicio_1.3/output/imagen_tux_cbc.png")

    header, pixels = read_ppm_header_and_pixels(str(ppm_input))
    key = generate_aes_key(256)
    iv = generate_iv(16)
    pixels_ecb = encrypt_ecb(pixels, key)
    pixels_cbc = encrypt_cbc(pixels, key, iv)

    write_ppm(str(ppm_ecb_out), header, pixels_ecb)
    write_ppm(str(ppm_cbc_out), header, pixels_cbc)
    Image.open(ppm_ecb_out).save(png_ecb_out, format="PNG")
    Image.open(ppm_cbc_out).save(png_cbc_out, format="PNG")

    print(f"KEY (hex): {key.hex()}")
    print(f"IV  (hex): {iv.hex()}")
    print(f"Salida ECB PPM: {ppm_ecb_out}")
    print(f"Salida CBC PPM: {ppm_cbc_out}")
    print(f"Salida ECB PNG: {png_ecb_out}")
    print(f"Salida CBC PNG: {png_cbc_out}")


def demo_ecb_cbc_text() -> None:
    print("\n=== Vulnerabilidad ECB vs CBC (texto repetido) ===")
    key = generate_aes_key(256)
    iv = generate_iv(16)

    # Mensaje solicitado en el enunciado
    ataque_msg = b"ATAQUE ATAQUE ATAQUE"
    ecb_cipher_ataque = AES.new(key, AES.MODE_ECB)
    cbc_cipher_ataque = AES.new(key, AES.MODE_CBC, iv=iv)
    ecb_ct_ataque = ecb_cipher_ataque.encrypt(pad(ataque_msg, 16))
    cbc_ct_ataque = cbc_cipher_ataque.encrypt(pad(ataque_msg, 16))
    print(f"Mensaje ejemplo: {ataque_msg!r}")
    print(f"ECB hex: {ecb_ct_ataque.hex()}")
    print(f"CBC hex: {cbc_ct_ataque.hex()}")

    # Demostracion de bloques identicos -> cifrados identicos en ECB
    repeated_block = b"ATAQUE ATAQUE!!!"  # 16 bytes exactos
    repeated_plaintext = repeated_block * 3
    ecb_cipher = AES.new(key, AES.MODE_ECB)
    cbc_cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    ecb_ct = ecb_cipher.encrypt(repeated_plaintext)
    cbc_ct = cbc_cipher.encrypt(repeated_plaintext)
    e1, e2, e3 = ecb_ct[:16], ecb_ct[16:32], ecb_ct[32:48]
    c1, c2, c3 = cbc_ct[:16], cbc_ct[16:32], cbc_ct[32:48]

    print("\nBloques de plaintext iguales?:", repeated_plaintext[:16] == repeated_plaintext[16:32] == repeated_plaintext[32:48])
    _print_blocks("ECB bloques", ecb_ct[:48])
    print("ECB C1==C2==C3?:", e1 == e2 == e3)
    _print_blocks("CBC bloques", cbc_ct[:48])
    print("CBC C1==C2==C3?:", c1 == c2 == c3)


def demo_iv_experiment() -> None:
    print("\n=== Experimento IV en CBC ===")
    key = generate_aes_key(256)
    msg = b"Mensaje sensible repetido para prueba de IV en CBC"

    iv_same = generate_iv(16)
    ct_same_1 = encrypt_cbc(msg, key, iv_same)
    ct_same_2 = encrypt_cbc(msg, key, iv_same)
    print("Caso 1 - MISMO IV")
    print(f"IV: {iv_same.hex()}")
    print(f"CT1: {ct_same_1.hex()}")
    print(f"CT2: {ct_same_2.hex()}")
    print(f"CT1 == CT2?: {ct_same_1 == ct_same_2}")

    iv_1 = generate_iv(16)
    iv_2 = generate_iv(16)
    ct_diff_1 = encrypt_cbc(msg, key, iv_1)
    ct_diff_2 = encrypt_cbc(msg, key, iv_2)
    print("\nCaso 2 - IV DIFERENTES")
    print(f"IV1: {iv_1.hex()}")
    print(f"IV2: {iv_2.hex()}")
    print(f"CT1: {ct_diff_1.hex()}")
    print(f"CT2: {ct_diff_2.hex()}")
    print(f"CT1 == CT2?: {ct_diff_1 == ct_diff_2}")


def demo_padding_experiment() -> None:
    print("\n=== Experimento PKCS#7 ===")
    cases = [b"HELLO", b"12345678", b"ABCDEFGHIJ"]
    for msg in cases:
        padded = pkcs7_pad(msg, 8)
        unpadded = pkcs7_unpad(padded)
        padding = padded[len(msg) :]

        print(f"\nMensaje: {msg!r} (len={len(msg)})")
        print(f"Padded (hex): {padded.hex()}")
        print(f"Padding agregado (hex): {padding.hex()}")
        print(f"Bytes de padding: {[b for b in padding]}")
        print(f"Unpad recupera original?: {unpadded == msg}")


def main() -> None:
    demo_des()
    demo_3des()
    demo_aes_image()
    demo_ecb_cbc_text()
    demo_iv_experiment()
    demo_padding_experiment()


if __name__ == "__main__":
    main()
