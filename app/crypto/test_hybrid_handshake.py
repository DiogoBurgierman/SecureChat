"""
Teste do handshake híbrido:
Diffie-Hellman clássico + ML-KEM (liboqs)

Este teste simula duas partes (Alice e Bob) e verifica:
- Igualdade da chave de sessão derivada
- Funcionamento da cifragem AES-128 com a chave híbrida
"""

from .dh import (
    generate_dh_private_key,
    serialize_dh_public_key,
    generate_mlkem_keypair,
    mlkem_encapsulate,
    mlkem_decapsulate,
    derive_hybrid_session_key,
)

from .aes import encrypt_aes128, decrypt_aes128


def test_hybrid_handshake():
    print("[TEST] Iniciando teste de handshake híbrido")

    # ======================================================
    # Alice (cliente)
    # ======================================================
    alice_dh_priv = generate_dh_private_key()
    alice_dh_pub = serialize_dh_public_key(
        alice_dh_priv.public_key()
    )

    alice_mlkem_pk, alice_mlkem_sk = generate_mlkem_keypair()

    # ======================================================
    # Bob (servidor)
    # ======================================================
    bob_dh_priv = generate_dh_private_key()
    bob_dh_pub = serialize_dh_public_key(
        bob_dh_priv.public_key()
    )

    # ======================================================
    # ML-KEM: encapsulamento / decapsulamento
    # ======================================================
    mlkem_ct, bob_mlkem_shared = mlkem_encapsulate(
        alice_mlkem_pk
    )

    alice_mlkem_shared = mlkem_decapsulate(
        alice_mlkem_sk,
        mlkem_ct,
    )

    # ======================================================
    # Derivação das chaves híbridas (DH + ML-KEM)
    # ======================================================
    alice_session_key = derive_hybrid_session_key(
        alice_dh_priv,
        bob_dh_pub,
        alice_mlkem_shared,
    )

    bob_session_key = derive_hybrid_session_key(
        bob_dh_priv,
        alice_dh_pub,
        bob_mlkem_shared,
    )

    print("[TEST] Chave Alice:", alice_session_key.hex())
    print("[TEST] Chave Bob:  ", bob_session_key.hex())

    # ======================================================
    # Verificação 1: chaves devem coincidir
    # ======================================================
    assert alice_session_key == bob_session_key, (
        "ERRO: chaves de sessão não coincidem"
    )

    print("[OK] Chaves de sessão coincidem")

    # ======================================================
    # Verificação 2: AES-128 usando chave híbrida
    # ======================================================
    mensagem = "Criptografia híbrida pós-quântica funcionando!"
    mensagem_bytes = mensagem.encode("utf-8")

    # AES-128 → 16 bytes da chave híbrida
    aes_key_alice = alice_session_key[:16]
    aes_key_bob = bob_session_key[:16]

    ciphertext = encrypt_aes128(
        mensagem_bytes,
        aes_key_alice,
    )

    plaintext = decrypt_aes128(
        ciphertext,
        aes_key_bob,
    )

    assert plaintext.decode("utf-8") == mensagem, (
        "ERRO: falha na cifragem AES com chave híbrida"
    )

    print("[OK] AES funcionou corretamente")
    print("[TEST] Teste concluído com sucesso 🎉")


if __name__ == "__main__":
    test_hybrid_handshake()
