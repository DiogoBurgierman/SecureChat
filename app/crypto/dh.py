#Implementação híbrida com algorítimo pós quântico desenvolvida por Diogo Burgierman, Lucas de Lucas e Andre Hutzler

# =========================
# IMPORTS PADRÃO
# =========================
from typing import Tuple
import os

# =========================
# CRYPTOGRAPHY (DH + HKDF)
# =========================
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# =========================
# OQS (ML-KEM direto)
# =========================
import oqs


# ==========================================================
# Diffie-Hellman CLÁSSICO
# ==========================================================

parameters = dh.generate_parameters(
    generator=2,
    key_size=2048,
)


def generate_dh_private_key():
    return parameters.generate_private_key()


def serialize_dh_public_key(public_key) -> bytes:
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def deserialize_dh_public_key(public_key_bytes: bytes):
    return serialization.load_pem_public_key(public_key_bytes)


def derive_dh_shared_secret(
    private_key,
    peer_public_key_bytes: bytes,
) -> bytes:
    peer_public_key = deserialize_dh_public_key(peer_public_key_bytes)
    return private_key.exchange(peer_public_key)


# ==========================================================
# ML-KEM (liboqs)
# ==========================================================

MLKEM_ALG = "ML-KEM-768"


def generate_mlkem_keypair() -> Tuple[bytes, bytes]:
    kem = oqs.KeyEncapsulationMechanism(MLKEM_ALG)
    pk = kem.generate_keypair()
    sk = kem.export_secret_key()
    return pk, sk


def mlkem_encapsulate(peer_public_key: bytes) -> Tuple[bytes, bytes]:
    kem = oqs.KeyEncapsulationMechanism(MLKEM_ALG)
    ciphertext, shared_secret = kem.encap(peer_public_key)
    return ciphertext, shared_secret


def mlkem_decapsulate(
    own_secret_key: bytes,
    ciphertext: bytes,
) -> bytes:
    kem = oqs.KeyEncapsulationMechanism(
        MLKEM_ALG,
        secret_key=own_secret_key,
    )
    shared_secret = kem.decap(ciphertext)
    return shared_secret


# ==========================================================
# DERIVAÇÃO HÍBRIDA FINAL
# ==========================================================

def derive_hybrid_session_key(
    dh_private_key,
    peer_dh_public_bytes: bytes,
    mlkem_shared_secret: bytes,
    key_length: int = 32,
) -> bytes:

    dh_shared_secret = derive_dh_shared_secret(
        dh_private_key,
        peer_dh_public_bytes,
    )

    combined_secret = dh_shared_secret + mlkem_shared_secret

    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=key_length,
        salt=None,
        info=b"securechat hybrid pq session key",
    ).derive(combined_secret)

    return derived_key
