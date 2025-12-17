"""
Teste do handshake híbrido:
Diffie-Hellman clássico + ML-KEM (liboqs)

Este teste simula duas partes (Alice e Bob) e verifica:
- Igualdade da chave de sessão derivada
- Funcionamento da cifragem AES com a chave híbrida
"""

from app.crypto.dh import (
    generate_dh_private_key,
    serialize_dh_public_key,
    generate_mlkem_keypair,
    mlkem_encapsulate,
    mlkem_decapsulate,
    derive_hybrid_session_key,
)

from app.crypto.aes import encrypt_message, decrypt_message


def test_hybrid_handshake():
    print("[TEST] Iniciando teste de handshake híbrido")

    # ======================================================
    # Alice (cliente)
    # ======================================================
    alice_dh_priv = generate_dh_private_key()
    alice_dh_pub = serialize_dh_public_key(alice_dh_priv.public_key())

    alice_mlkem_pk, alice_mlkem_sk = generate_mlkem_keypair()

    # ======================================================
    # Bob (servidor)
    # ======================================================
    bob_dh_priv = generate_dh_private_key()
    bob_dh_pub = serialize_dh_public_key(bob_dh_priv.public_key())

    # Bob encapsula usando a chave ML-KEM da Alice
    mlkem_ct, bob_mlkem_shared = mlkem_encapsulate(alice_mlkem_pk)

    # Alice decapsula
    alice_mlkem_shared = mlkem_decapsulate(
        alice_mlkem_sk,
        mlkem_ct,
    )

    # ======================================================
    # Derivação das chaves híbridas
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
    # Verificação 1: igualdade das chaves
    # ======================================================
    assert alice_session_key == bob_session_key, \
        "ERRO: chaves de sessão não coincidem"

    print("[OK] Chaves de sessão coincidem")

    # ======================================================
    # Verificação 2: AES funciona com chave híbrida
    # ======================================================
    mensagem = "Criptografia híbrida pós-quântica funcionando!"
    ciphertext = encrypt_message(alice_session_key, mensagem)
    plaintext = decrypt_message(bob_session_key, ciphertext)

    assert plaintext == mensagem, \
        "ERRO: falha na cifragem AES com chave híbrida"

    print("[OK] AES funcionou corretamente")
    print("[TEST] Teste concluído com sucesso 🎉")


if __name__ == "__main__":
    test_hybrid_handshake()
