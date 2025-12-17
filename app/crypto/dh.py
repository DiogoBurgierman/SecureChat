# app/crypto/dh.py
#
# Handshake híbrido:
# Diffie-Hellman clássico + ML-KEM (liboqs)
#
# Chave final:
#   K = HKDF( DH_shared || MLKEM_shared )
#

# =========================
# IMPORTS PADRÃO
# =========================
from typing import Tuple

# =========================
# CRYPTOGRAPHY (DH + HKDF)
# =========================
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# =========================
# ML-KEM (liboqs wrapper)
# =========================
from app.crypto.oqs_kem import MLKEM


# ==========================================================
# Diffie-Hellman CLÁSSICO
# ==========================================================

# Parâmetros DH globais (mesmos para cliente e servidor)
parameters = dh.generate_parameters(
    generator=2,
    key_size=2048,
)


def generate_dh_private_key():
    """
    Gera chave privada Diffie-Hellman.
    """
    return parameters.generate_private_key()


def serialize_dh_public_key(public_key) -> bytes:
    """
    Serializa chave pública DH para envio em rede.
    """
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def deserialize_dh_public_key(public_key_bytes: bytes):
    """
    Desserializa chave pública DH recebida.
    """
    return serialization.load_pem_public_key(public_key_bytes)


def derive_dh_shared_secret(
    private_key,
    peer_public_key_bytes: bytes,
) -> bytes:
    """
    Calcula segredo compartilhado DH.
    """
    peer_public_key = deserialize_dh_public_key(peer_public_key_bytes)
    return private_key.exchange(peer_public_key)


# ==========================================================
# ML-KEM (PÓS-QUÂNTICO) — liboqs
# ==========================================================

def generate_mlkem_keypair() -> Tuple[bytes, bytes]:
    """
    Gera par de chaves ML-KEM.
    Retorna: (public_key, secret_key)
    """
    kem = MLKEM()
    pk, sk = kem.keypair()
    return pk, sk


def mlkem_encapsulate(peer_public_key: bytes) -> Tuple[bytes, bytes]:
    """
    Encapsula usando a chave pública ML-KEM do peer.
    Retorna: (ciphertext, shared_secret)
    """
    kem = MLKEM()
    ciphertext, shared_secret = kem.encapsulate(peer_public_key)
    return ciphertext, shared_secret


def mlkem_decapsulate(
    own_secret_key: bytes,
    ciphertext: bytes,
) -> bytes:
    """
    Decapsula ciphertext ML-KEM e recupera o shared secret.
    """
    kem = MLKEM()
    return kem.decapsulate(own_secret_key, ciphertext)


# ==========================================================
# DERIVAÇÃO HÍBRIDA FINAL
# ==========================================================

def derive_hybrid_session_key(
    dh_private_key,
    peer_dh_public_bytes: bytes,
    mlkem_shared_secret: bytes,
    key_length: int = 32,
) -> bytes:
    """
    Deriva chave de sessão híbrida:
        HKDF( DH_shared || MLKEM_shared )

    Args:
        dh_private_key: chave privada DH local
        peer_dh_public_bytes: chave pública DH do peer (serializada)
        mlkem_shared_secret: segredo compartilhado ML-KEM
        key_length: tamanho da chave final (default: 32 bytes)

    Returns:
        Chave simétrica derivada (bytes)
    """

    # 1. Segredo clássico DH
    dh_shared_secret = derive_dh_shared_secret(
        dh_private_key,
        peer_dh_public_bytes,
    )

    # 2. Combinação híbrida (modelo NIST)
    combined_secret = dh_shared_secret + mlkem_shared_secret

    # 3. Derivação via HKDF
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=key_length,
        salt=None,
        info=b"securechat hybrid pq session key",
    ).derive(combined_secret)

    return derived_key
