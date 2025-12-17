# app/crypto/oqs_kem.py

import ctypes
import ctypes.util

# Carrega liboqs
_liboqs_path = ctypes.util.find_library("oqs")
if not _liboqs_path:
    raise RuntimeError("liboqs não encontrada. Instale liboqs no sistema.")

liboqs = ctypes.CDLL(_liboqs_path)

# --- Estruturas e constantes ---
OQS_SUCCESS = 0

class OQS_KEM(ctypes.Structure):
    pass

liboqs.OQS_KEM_new.restype = ctypes.POINTER(OQS_KEM)
liboqs.OQS_KEM_new.argtypes = [ctypes.c_char_p]

liboqs.OQS_KEM_free.argtypes = [ctypes.POINTER(OQS_KEM)]

liboqs.OQS_KEM_keypair.argtypes = [
    ctypes.POINTER(OQS_KEM),
    ctypes.c_void_p,
    ctypes.c_void_p,
]

liboqs.OQS_KEM_encaps.argtypes = [
    ctypes.POINTER(OQS_KEM),
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.c_void_p,
]

liboqs.OQS_KEM_decaps.argtypes = [
    ctypes.POINTER(OQS_KEM),
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.c_void_p,
]

# Algoritmo ML-KEM padronizado (FIPS-203)
MLKEM_ALG = b"ML-KEM-768"


class MLKEM:
    def __init__(self):
        self.kem = liboqs.OQS_KEM_new(MLKEM_ALG)
        if not self.kem:
            raise RuntimeError("Falha ao inicializar ML-KEM")

        # tamanhos (lidos da struct em runtime)
        self.pk_len = ctypes.c_size_t.from_address(
            ctypes.addressof(self.kem.contents) + 0
        ).value

    def keypair(self):
        pk = ctypes.create_string_buffer(self.kem.contents.length_public_key)
        sk = ctypes.create_string_buffer(self.kem.contents.length_secret_key)

        rc = liboqs.OQS_KEM_keypair(self.kem, pk, sk)
        if rc != OQS_SUCCESS:
            raise RuntimeError("Erro ao gerar keypair ML-KEM")

        return pk.raw, sk.raw

    def encapsulate(self, peer_pk: bytes):
        ct = ctypes.create_string_buffer(self.kem.contents.length_ciphertext)
        ss = ctypes.create_string_buffer(self.kem.contents.length_shared_secret)

        rc = liboqs.OQS_KEM_encaps(self.kem, ct, ss, peer_pk)
        if rc != OQS_SUCCESS:
            raise RuntimeError("Erro no encapsulate ML-KEM")

        return ct.raw, ss.raw

    def decapsulate(self, sk: bytes, ct: bytes):
        ss = ctypes.create_string_buffer(self.kem.contents.length_shared_secret)

        rc = liboqs.OQS_KEM_decaps(self.kem, ss, ct, sk)
        if rc != OQS_SUCCESS:
            raise RuntimeError("Erro no decapsulate ML-KEM")

        return ss.raw

    def __del__(self):
        if self.kem:
            liboqs.OQS_KEM_free(self.kem)
