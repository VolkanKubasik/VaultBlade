 #VaultBlade
A powerful, single-file cryptography toolkit featuring hashing, password hashing, file encryption (XChaCha20/AES-GCM), Ed25519 signatures, HMAC, and Merkle tree hashing — all in one Python script.

 #VaultBlade

**VaultBlade** is a powerful **single-file cryptography toolkit** written in Python.  
It provides modern hashing, password hashing, authenticated file encryption, HMAC, Ed25519 signatures, and Merkle tree hashing — all in **one script** with no project setup required.

This tool is ideal for:
- Cybersecurity learning & demonstration
- Cryptography research
- Secure file handling
- CTFs and hacking challenges
- Local encryption workflows
- Offline security utilities

---

## Features

| Category | Capabilities |
|---------|-------------|
| Hashing | SHA-256, SHA3-256, BLAKE2b |
| HMAC | HMAC-SHA256 for text and files |
| Password Hashing | Argon2id, Scrypt, PBKDF2 + verification |
| File Encryption | XChaCha20-Poly1305 (default) or AES-GCM |
| Public-Key Signatures | Ed25519: keygen, sign, verify |
| Tree Hashing | Merkle root across multiple files (SHA-256) |

---

## Requirements

```bash
pip install cryptography argon2-cffi
