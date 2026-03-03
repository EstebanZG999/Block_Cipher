# Prompt: ayudame con los tests para el codigo de los ciphers que tengo. 

from pathlib import Path

import pytest
from Crypto.Cipher import DES3
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from PIL import Image

from src.aes_cipher import (
    encrypt_cbc,
    encrypt_ecb,
    png_to_ppm,
    read_ppm_header_and_pixels,
    write_ppm,
)
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
    """Avoid random weak/invalid 3DES keys causing flaky tests."""
    for _ in range(100):
        key = generate_3des_key(key_option)
        try:
            DES3.new(key, DES3.MODE_CBC, iv=b"\x00" * 8)
            return key
        except ValueError:
            continue
    raise AssertionError("No se pudo generar una clave 3DES valida tras 100 intentos")


def test_key_and_iv_generation_sizes():
    assert len(generate_des_key()) == 8
    assert len(generate_3des_key(2)) == 16
    assert len(generate_3des_key(3)) == 24
    assert len(generate_aes_key(256)) == 32
    assert len(generate_iv(8)) == 8
    assert len(generate_iv(16)) == 16


def test_des_ecb_round_trip_with_lab_text():
    key = generate_des_key()
    ciphertext = encrypt_des_ecb(DES_LAB_TEXT, key)
    recovered = decrypt_des_ecb(ciphertext, key)

    assert len(ciphertext) % 8 == 0
    assert recovered == DES_LAB_TEXT


def test_des_ecb_invalid_ciphertext_raises():
    key = generate_des_key()
    with pytest.raises(ValueError):
        decrypt_des_ecb(b"12345", key)


@pytest.mark.parametrize("key_option", [2, 3])
def test_3des_cbc_round_trip_with_lab_text(key_option: int):
    key = _valid_3des_key(key_option)
    iv = generate_iv(8)

    ciphertext = encrypt_3des_cbc(TRIPLEDES_LAB_TEXT, key, iv)
    recovered = decrypt_3des_cbc(ciphertext, key, iv)

    assert len(ciphertext) % 8 == 0
    assert recovered == TRIPLEDES_LAB_TEXT


def test_3des_cbc_invalid_ciphertext_raises():
    key = _valid_3des_key(2)
    iv = generate_iv(8)
    with pytest.raises(ValueError):
        decrypt_3des_cbc(b"12345", key, iv)


def test_pkcs7_padding_cases_and_unpad_roundtrip():
    cases = [
        (b"HELLO", b"\x03\x03\x03"),
        (b"12345678", b"\x08" * 8),
        (b"ABCDEFGHIJ", b"\x06" * 6),
    ]

    for message, expected_padding in cases:
        padded = pkcs7_pad(message, 8)
        assert padded.endswith(expected_padding)
        assert pkcs7_unpad(padded) == message


def test_ecb_vs_cbc_repeated_blocks_experiment():
    key = generate_aes_key(256)
    iv = generate_iv(16)
    repeated_block = b"ATAQUE ATAQUE!!!"  # 16 bytes
    plaintext = repeated_block * 3

    ecb_ct = encrypt_ecb(plaintext, key)
    cbc_ct = encrypt_cbc(plaintext, key, iv)

    e1, e2, e3 = ecb_ct[:16], ecb_ct[16:32], ecb_ct[32:48]
    c1, c2, c3 = cbc_ct[:16], cbc_ct[16:32], cbc_ct[32:48]

    assert e1 == e2 == e3
    assert not (c1 == c2 == c3)


def test_ecb_vs_cbc_ataque_example_message():
    key = generate_aes_key(256)
    iv = generate_iv(16)
    plaintext = b"ATAQUE ATAQUE ATAQUE"

    ecb_cipher = AES.new(key, AES.MODE_ECB)
    cbc_cipher = AES.new(key, AES.MODE_CBC, iv=iv)

    ecb_ct = ecb_cipher.encrypt(pad(plaintext, 16))
    cbc_ct = cbc_cipher.encrypt(pad(plaintext, 16))

    assert ecb_ct != cbc_ct


def test_iv_experiment_same_iv_same_ciphertext():
    key = generate_aes_key(256)
    iv = generate_iv(16)
    message = b"Mensaje sensible repetido para prueba de IV en CBC"

    ct1 = encrypt_cbc(message, key, iv)
    ct2 = encrypt_cbc(message, key, iv)

    assert ct1 == ct2


def test_iv_experiment_different_iv_different_ciphertext():
    key = generate_aes_key(256)
    message = b"Mensaje sensible repetido para prueba de IV en CBC"
    iv1 = generate_iv(16)
    iv2 = generate_iv(16)

    ct1 = encrypt_cbc(message, key, iv1)
    ct2 = encrypt_cbc(message, key, iv2)

    assert ct1 != ct2


def test_aes_image_processing_preserves_header_and_writes_outputs(tmp_path: Path):
    input_png = tmp_path / "input.png"
    converted_ppm = tmp_path / "converted.ppm"
    out_ecb_ppm = tmp_path / "out_ecb.ppm"
    out_cbc_ppm = tmp_path / "out_cbc.ppm"

    # Simple RGB test image
    Image.new("RGB", (16, 16), color=(10, 120, 200)).save(input_png, format="PNG")

    png_to_ppm(str(input_png), str(converted_ppm))
    header, pixels = read_ppm_header_and_pixels(str(converted_ppm))

    key = generate_aes_key(256)
    iv = generate_iv(16)
    pixels_ecb = encrypt_ecb(pixels, key)
    pixels_cbc = encrypt_cbc(pixels, key, iv)

    assert len(pixels_ecb) == len(pixels)
    assert len(pixels_cbc) == len(pixels)

    write_ppm(str(out_ecb_ppm), header, pixels_ecb)
    write_ppm(str(out_cbc_ppm), header, pixels_cbc)

    ecb_data = out_ecb_ppm.read_bytes()
    cbc_data = out_cbc_ppm.read_bytes()
    assert ecb_data.startswith(header)
    assert cbc_data.startswith(header)
    assert len(ecb_data) == len(header) + len(pixels)
    assert len(cbc_data) == len(header) + len(pixels)
