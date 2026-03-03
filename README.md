# Block_Cipher - Laboratorio de Cifrados de Bloque

Este repositorio implementa la entrega del laboratorio organizada por partes:

- Parte 1: Implementacion de cifrados de bloque (DES, 3DES, AES)
- Parte 2: Respuestas de analisis fundamentadas
- Parte 3: Testing y comparacion visual ECB vs CBC

---

## 1. Estructura del proyecto

```text
Block_Cipher/
|- src/
|  |- des_cipher.py
|  |- tripledes_cipher.py
|  |- aes_cipher.py
|  |- utils.py
|- ejercicios_avances/
|  |- generacion_llaves.py
|  |- manual_padding.py
|- images/
|  |- ejercicio_1.3/
|     |- input/
|     |- output/
|- tests/
|- requirements.txt
|- README.md
```

---

## 2. Instalacion

### 2.1 Requisitos
- Python 3.10+
- pip

### 2.2 Entorno virtual (opcional)

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

### 2.3 Dependencias

```powershell
pip install -r requirements.txt
```

Dependencias:
- `pycryptodome`
- `Pillow`
- `pytest`

---

## 3. Parte 1 - Implementacion y ejecucion

> Ejecutar siempre desde la raiz del repositorio.

### 3.1 Seccion 1.1 - DES en modo ECB

Archivo: `src/des_cipher.py`

Ejecucion:

Incluye:
- Generacion segura de clave DES (8 bytes)
- Padding PKCS#7 manual (reutilizado desde avances)
- Cifrado y descifrado ECB
- Verificacion de round-trip (descifrado recupera original)

### 3.2 Seccion 1.2 - 3DES en modo CBC

Archivo: `src/tripledes_cipher.py`

Incluye:
- Claves 3DES de 16 bytes (2-key) y 24 bytes (3-key)
- IV aleatorio por operacion
- `pad/unpad` de `Crypto.Util.Padding`
- Round-trip correcto en ambos esquemas

Diferencia 3DES 2-key vs 3-key
En 3DES se aplica el algoritmo DES tres veces bajo el esquema Encrypt–Decrypt–Encrypt (EDE). Cuando se utilizan 16 bytes (2 claves), en esta configuración se usan dos claves independientes K1 y K2, lo cual hace que la tercera clave sea igual a la primera (K3 = K1), lo que se conoce como 2TDEA. Cuando se utilizan 24 bytes (3 claves), se utilizan tres claves diferentes e independientes una de otra K1, K2 y K3, conocido como 3TDEA. Aunque en teoría usar 3 claves parece ofrecer 168 bits de seguridad (3 × 56 bits), en la práctica la seguridad efectiva es de aproximadamente 112 bits debido a ataques como meet-in-the-middle. La principal diferencia entre ambas configuraciones es que la versión de 3 claves evita reutilizar K1 como K3. 

Manejo de IV en 3DES-CBC
En CBC, el IV debe ser único/aleatorio por mensaje.  
Para transmitir el resultado de cifrado, se recomienda concatenar el IV al inicio del ciphertext:

- Formato: `payload = IV || CIPHERTEXT`
- Tamaño IV 3DES-CBC: 8 bytes

En el receptor:
1. Leer los primeros 8 bytes como `iv`.
2. Tomar el resto como `ciphertext`.
3. Ejecutar `decrypt_3des_cbc(ciphertext, key, iv)`.


### 3.3 Seccion 1.3 - AES en ECB y CBC (analisis visual)

Archivo: `src/aes_cipher.py`

Incluye:
- AES-256 (clave de 32 bytes)
- ECB y CBC
- IV aleatorio de 16 bytes para CBC
- Conservacion de header de imagen PPM y cifrado solo del body (pixeles)
- Salidas para comparacion visual:
  - `images/ejercicio_1.3/output/imagen_tux_ecb.ppm`
  - `images/ejercicio_1.3/output/imagen_tux_cbc.ppm`
  - `images/ejercicio_1.3/output/imagen_tux_ecb.png`
  - `images/ejercicio_1.3/output/imagen_tux_cbc.png`


Ejecucion de la parte 1:

```powershell
python -m tests.demo_outputs
```
---

## 4. Parte 2 - Preguntas de analisis (fundamentadas)

### 4.1 Pregunta: ¿Qué tamaño de clave está usando para DES, 3DES y AES? Para cada uno:
### Indique el tamaño en bits y bytes
### Explique por qué DES se considera inseguro hoy en día
### Calcule cuánto tiempo tomaría un ataque de fuerza bruta con hardware moderno

### DES: 

Tamaño de clave de 8 bytes (64 bits)
Seguridad efectiva: 56 bits (8 bits son de paridad)

Por que el DES es inseguro hoy: 

- Su espacio de claves es de solo 2^56, lo cual es demasiado pequeño.
- Puede romperse mediante ataques de fuerza bruta con hardware moderno.
- Fue oficialmente declarado inseguro y está obsoleto en estándares actuales.

Tiempo total en fuerza bruta:

Espacio total 2^56 = 7.2 x 10^16 claves
Promedio necesario 2^55 = 3.6 x 10^16
A 10^12 claves/seg se necesitaria 10 horas aproximadamente

### 3DES:

Tamano de clave:
- 16 bytes = 128 bits almacenados (2 claves)
- 24 bytes = 192 bits almacenados (3 claves)
- Seguridad efectiva aproximada: 112 bits

Tiempo estimado de fuerza bruta:

Seguridad efectiva = 112 bits
Espacio promedio: 2^111 = 2.6 x 10^33 CLAVES
A 10^12 claves/segundo = 8.2 x 10^13 años

### AES

Tamano de clave:

-32 bytes = 256 bits
- Seguridad efectiva: 256 bits

Tiempo estimado de fuerza bruta:

Espacio promedo: 2^255 = 5.7 x 10^76 claves
A 10^12 claves/segundo = 1.8 x 10^57 años


```text
import secrets

des_key  = secrets.token_bytes(8)    # 8 bytes (64 bits) -> 56 bits efectivos
tdes_k2  = secrets.token_bytes(16)   # 16 bytes (2-key 3DES)
tdes_k3  = secrets.token_bytes(24)   # 24 bytes (3-key 3DES)
aes_key  = secrets.token_bytes(32)   # 32 bytes (AES-256)

print(len(des_key), len(tdes_k2), len(tdes_k3), len(aes_key))
```


### 4.2 Compare ECB vs CBC mostrando:
### o	¿Qué modo de operación implementó en cada algoritmo?
### o	¿Cuáles son las diferencias fundamentales entre ECB y CBC?
### o	¿Se puede notar la diferencia directamente en una imagen?

En esta práctica se implementó DES en modo ECB, 3DES en modo CBC, y AES tanto en ECB como en CBC para análisis visual. La diferencia fundamental entre ECB y CBC esta en que ECB cifra cada bloque de manera independiente, mientras que CBC encadena los bloques mediante una operación XOR con el bloque cifrado anterior y un vector de inicialización (IV) en el primer bloque. Debido a esta independencia, ECB produce bloques cifrados idénticos cuando los bloques de texto plano son idénticos, lo que permite que se preserven patrones estructurales. En el caso del cifrado de imágenes con AES, la imagen cifrada en ECB conserva contornos y patrones reconocibles, mientras que la versión en CBC elimina completamente dichas estructuras, produciendo un resultado visual similar a ruido aleatorio. Esta diferencia demuestra por qué ECB no es adecuado para datos sensibles.

### Evidencia visual (Original vs ECB vs CBC)

<table>
  <tr>
    <th>Original</th>
    <th>AES-ECB</th>
    <th>AES-CBC</th>
  </tr>
  <tr>
    <td><img src="images/ejercicio_1.3/input/tux.png" width="260"></td>
    <td><img src="images/ejercicio_1.3/output/imagen_tux_ecb.png" width="260"></td>
    <td><img src="images/ejercicio_1.3/output/imagen_tux_cbc.png" width="260"></td>
  </tr>
</table>

Sí. En ECB, se preservan patrones/contornos.
En CBC, la imagen cifrada parece ruido, sin patrones visibles.

#### Código exacto usado para generar las imágenes

Archivo: `src/aes_cipher.py`

```python
# 2) Leer header + pixeles
header, pixels = read_ppm_header_and_pixels(ppm_input)

# 3) Generar clave AES-256 e IV para CBC
key = generate_aes_key(256)  # 32 bytes
iv = generate_iv(16)         # AES block size

# 4) Cifrar solo pixeles (header intacto)
pixels_ecb = encrypt_ecb(pixels, key)
pixels_cbc = encrypt_cbc(pixels, key, iv)

# 5) Guardar resultados PPM
write_ppm(ppm_ecb_out, header, pixels_ecb)
write_ppm(ppm_cbc_out, header, pixels_cbc)

# 6) Convertir outputs PPM -> PNG para visualizacion
Image.open(ppm_ecb_out).save(png_ecb_out, format="PNG")
Image.open(ppm_cbc_out).save(png_cbc_out, format="PNG")
```

### 4.3 ¿Por qué no debemos usar ECB en datos sensibles?
El modo ECB no debe utilizarse para datos sensibles porque revela patrones estructurales del mensaje original. Cuando un mensaje contiene bloques idénticos, el cifrado en ECB produce bloques cifrados idénticos, lo que permite a un observador detectar repeticiones. Por ejemplo, al cifrar una cadena repetitiva como “ATAQUE ATAQUE ATAQUE” dividida en bloques, el resultado en hexadecimal muestra bloques repetidos bajo ECB, mientras que bajo CBC los bloques difieren debido al encadenamiento con el bloque anterior y el IV. Esta propiedad puede filtrar información relevante en escenarios reales, como detectar estructuras repetidas en bases de datos, encabezados de archivos, campos constantes en registros o incluso siluetas en imágenes cifradas. Aunque el contenido exacto no sea visible, la estructura del mensaje sí se expone, lo que representa una fuga de información.

```text === Demo texto repetido: ECB vs CBC ===
Bloques plaintext iguales?: True
ECB C1: ade8d3fd9bb57fbc22981ede76d53e43
ECB C2: ade8d3fd9bb57fbc22981ede76d53e43
ECB C3: ade8d3fd9bb57fbc22981ede76d53e43
ECB C1==C2==C3?: True
CBC C1: da011301c3b6d00d059c2e0e8344e0a0
CBC C2: 7bf6dc2793ac5c5d692da1897e2cf42d
CBC C3: d212c1f3e2346317ff1fa58eddaa8557
CBC C1==C2==C3?: False
```

### 4.4 ¿Qué es el IV y por qué es necesario en CBC pero no en ECB?
El Vector de Inicialización (IV) es un valor aleatorio del tamaño del bloque que se utiliza en modos encadenados como CBC para introducir aleatoriedad en el primer bloque cifrado. En ECB no es necesario un IV porque cada bloque se cifra de forma independiente, mientras que en CBC el IV es una parte importante del cipher para garantizar que el mismo mensaje cifrado dos veces produzca resultados distintos. 

```text 
=== Caso 1: MISMO IV ===
IV: 71f296d38aa82563ea8215ac3685f5b8
CT1: 450bea05229897e8a9e178ec80f295057a8d75249fad7c784984b80a3e684c2de2b90727dd4dc0d0aff17ac738fbe554f793f3c3a16d2847bc2414e64bd77aec
CT2: 450bea05229897e8a9e178ec80f295057a8d75249fad7c784984b80a3e684c2de2b90727dd4dc0d0aff17ac738fbe554f793f3c3a16d2847bc2414e64bd77aec
CT1 == CT2 ? True

=== Caso 2: IV DIFERENTE ===
IV A: fd598924210c6073bc28fcf30d9525a2
IV B: 816331121f9e9ae0a956d97a2f9d58eb
CT1: ae90505a44cb02537406f471c5dfc51cf85676abebaa118ed6a9b56d145129b7859fc0f1361179d65ecf91a443347ad54b9bbce059efe1912fbec682d4ec748a
CT2: 69315243a5d810c1be9e91d7b2ab94124675c7f8dc4f9a67956399aa4e748017ecf56067dc7e301e9939f9eb2acb11732ae962163bb78049a44bb3fc175c79f6
CT1 == CT2 ? False
```

En el experimento realizado, al cifrar el mismo mensaje dos veces usando el mismo IV en CBC, se obtuvo el mismo resultado cifrado, lo que demuestra que la reutilización del IV elimina la aleatoriedad esperada. En cambio, cuando se utilizaron IVs diferentes, los resultados cifrados fueron distintos. Si un atacante intercepta mensajes cifrados con el mismo IV, puede detectar repeticiones y realizar análisis estadísticos que comprometan la confidencialidad del sistema.


### 4.5 ¿Qué es el padding y por qué es necesario?
El padding es un mecanismo que permite que un mensaje cuya longitud no es múltiplo del tamaño de bloque pueda cifrarse correctamente. En esta implementación se utilizó PKCS#7, que agrega N bytes al final del mensaje, donde cada byte tiene el valor N, siendo N la cantidad de bytes necesarios para completar el bloque. La función pkcs7_unpad elimina estos bytes verificando que todos los bytes finales coincidan con el valor esperado, recuperando así el mensaje original. Este mecanismo garantiza que el descifrado sea correcto y evita ambigüedades en la longitud del mensaje original.

Mensaje original: b'HELLO' (len=5)
Padded (hex): 48454c4c4f030303
Ultimos bytes (padding): 030303
Recuperado igual?: True

En el primer caso (mensaje de 5 bytes), el tamaño del bloque es de 8 bytes, por lo que faltaban 3 bytes para completar el bloque. Según PKCS#7, se agregan 3 bytes y cada uno tiene el valor 0x03, indicando que se añadieron tres bytes de padding.

Mensaje original: b'12345678' (len=8)
Padded (hex): 31323334353637380808080808080808
Ultimos bytes (padding): 0808080808080808
Recuperado igual?: True

En el segundo caso (mensaje de 8 bytes), el mensaje ya era exactamente un bloque completo. Sin embargo, PKCS#7 requiere agregar un bloque completo adicional para evitar ambigüedad al descifrar. Por ello se agregaron 8 bytes, cada uno con el valor 0x08.

Mensaje original: b'ABCDEFGHIJ' (len=10)
Padded (hex): 4142434445464748494a060606060606
Ultimos bytes (padding): 060606060606
Recuperado igual?: True

En el tercer caso (mensaje de 10 bytes), 10 mod 8 = 2, lo que significa que faltaban 6 bytes para completar el siguiente bloque. Por lo tanto, se agregaron 6 bytes con valor 0x06, indicando que el padding ocupa seis posiciones.


### 4.6 ¿En qué situaciones se recomienda cada modo de operación? ¿Cómo elegir un modo seguro en cada lenguaje de programación?
El modo ECB no se recomienda para datos sensibles debido a que revela patrones estructurales y no proporciona seguridad semántica. CBC puede utilizarse en sistemas heredados siempre que se emplee un IV aleatorio y se combine con un mecanismo adicional de autenticación, ya que por sí solo no garantiza integridad. CTR es adecuado para aplicaciones de alto rendimiento y cifrado tipo streaming, ya que no requiere padding y puede paralelizarse, pero requiere extremo cuidado en la gestión del nonce o contador, ya que su reutilización compromete completamente la seguridad.

El modo GCM es un modo AEAD (Authenticated Encryption with Associated Data), lo que significa que proporciona simultáneamente confidencialidad e integridad mediante un tag de autenticación. Si el tag no coincide durante el descifrado, la operación falla, garantizando que el mensaje no ha sido alterado. En la práctica moderna, AES-GCM es el estándar recomendado en la mayoría de lenguajes y bibliotecas criptográficas, siempre asegurando que el nonce no se reutilice y que se transmita junto con el ciphertext (por ejemplo, concatenado al inicio).

#### Tabla comparativa de modos

| Modo | ¿Recomendado hoy? | Casos de uso | Ventajas | Desventajas / Riesgos |
|---|---|---|---|---|
| ECB | No | Solo demos académicas | Simple | Filtra patrones; no seguridad semántica |
| CBC | Condicional (sistemas heredados) | Compatibilidad legacy | Amplio soporte histórico | Requiere IV aleatorio y autenticación aparte (no integridad por sí solo) |
| CTR | Sí, con cuidado | Streaming, alto rendimiento, paralelo | No requiere padding, rápido | Reutilizar nonce/contador rompe seguridad |
| GCM (AEAD) | Sí (preferido) | APIs modernas, tráfico de red, datos sensibles | Confidencialidad + integridad (tag), rendimiento alto | Requiere nonce único; mal manejo del nonce compromete seguridad |

### Ejemplos de código en 2 lenguajes (modo seguro: GCM)

#### Python (PyCryptodome) - AES-GCM
```python
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

key = get_random_bytes(32)          # AES-256
nonce = get_random_bytes(12)        # recomendado para GCM
plaintext = b"mensaje sensible"

cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
ciphertext, tag = cipher.encrypt_and_digest(plaintext)

# En una implementación real, el nonce se transmite junto al ciphertext

# Descifrado + verificación de integridad
cipher_dec = AES.new(key, AES.MODE_GCM, nonce=nonce)
recovered = cipher_dec.decrypt_and_verify(ciphertext, tag)
print(recovered)
```

```java
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.security.SecureRandom;

KeyGenerator kg = KeyGenerator.getInstance("AES");
kg.init(256);
SecretKey key = kg.generateKey();

byte[] nonce = new byte[12];
new SecureRandom().nextBytes(nonce);

Cipher enc = Cipher.getInstance("AES/GCM/NoPadding");
GCMParameterSpec spec = new GCMParameterSpec(128, nonce);
enc.init(Cipher.ENCRYPT_MODE, key, spec);

byte[] plaintext = "mensaje sensible".getBytes();
byte[] ciphertextWithTag = enc.doFinal(plaintext);

// En producción, el nonce debe enviarse junto al ciphertext

// Descifrado (valida automáticamente el tag)
Cipher dec = Cipher.getInstance("AES/GCM/NoPadding");
dec.init(Cipher.DECRYPT_MODE, key, spec);
byte[] recovered = dec.doFinal(ciphertextWithTag);
```
---

## 5. Testing y evidencia visual

### 5.1 Proceso de testing
Se implementaron pruebas automatizadas con `pytest` en [tests/test_ciphers.py]

Cobertura actual:

1. DES ECB
- validaciones de tipo y longitud de clave
- round-trip con el texto del laboratorio
- manejo de ciphertext invalido

2. 3DES CBC
- pruebas con clave de 16 bytes (2-key) y 24 bytes (3-key)
- IV de 8 bytes
- round-trip correcto
- manejo de ciphertext invalido

3. AES ECB/CBC
- experimento de bloques repetidos (ECB vs CBC)
- experimento con mensaje `ATAQUE ATAQUE ATAQUE`
- experimento de IV (mismo IV vs IVs diferentes)

4. Padding PKCS#7
- casos de 5, 8 y 10 bytes
- verificacion de `pkcs7_unpad(pkcs7_pad(msg)) == msg`

5. Imagen AES
- lectura y validacion de PPM
- preservacion de header
- cifrado del body
- generacion y escritura de salidas

Ejecucion de pruebas:

```powershell
python -m pytest -q
```

Resultado actual:
- `12 passed`

Para ver salidas detalladas, se incluye el script:

```powershell
python -m tests.demo_outputs
```

### 5.2 Comparacion visual ECB vs CBC
Resultados esperados:
- ECB: se observan patrones de la imagen original
- CBC: apariencia de ruido, sin estructura reconocible

Archivos:
- `images/ejercicio_1.3/output/imagen_tux_ecb.png`
- `images/ejercicio_1.3/output/imagen_tux_cbc.png`

Conclusion:
ECB filtra informacion estructural; CBC evita esa fuga visual gracias al encadenamiento y al IV aleatorio.

<table>
  <tr>
    <th>Original</th>
    <th>AES-ECB</th>
    <th>AES-CBC</th>
  </tr>
  <tr>
    <td><img src="images/ejercicio_1.3/input/tux.png" width="260"></td>
    <td><img src="images/ejercicio_1.3/output/imagen_tux_ecb.png" width="260"></td>
    <td><img src="images/ejercicio_1.3/output/imagen_tux_cbc.png" width="260"></td>
  </tr>
</table>
---

## 6. Cierre

- Se reutilizaron funciones de `ejercicios_avances` a traves de `src/utils.py`
- Parte 1 implementada en `src/des_cipher.py`, `src/tripledes_cipher.py`, `src/aes_cipher.py`
- Parte 2 documentada en la seccion 4
- Tests documentados en la seccion 5
