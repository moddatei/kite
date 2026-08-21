# Security Architecture & Threat Model for Kite

## 1. Threat Model & Adversary Assumptions

Kite assumes an active, state-level adversary capable of:
* Full passive RF spectrum monitoring and packet capture.
* Deep Packet Inspection (DPI) and statistical entropy classification.
* Injecting arbitrary forged frames into physical mediums (802.11 / LoRa).
* Compromising physical intermediate relay nodes.

### Security Guarantees
* **Forward Secrecy:** Ephemeral keys are wiped from RAM immediately following Diffie-Hellman ratchet steps. Compromising a node's long-term static key does not compromise past captured sessions.
* **Identity Hiding:** Public static keys are never transmitted in plaintext over the air. In the `Noise_XX` pattern, static keys are encrypted under the ephemeral Diffie-Hellman secret.
* **DPI Evasion (Stochastic Masking):** Transmitted packets pass statistical NIST STS uniformity tests to prevent signature detection on RF monitoring stations.

---

## 2. Cryptographic Primitives

| Purpose | Primitive | Security Strength |
| :--- | :--- | :--- |
| Key Exchange | X25519 (Curve25519) | 128-bit security level |
| Authenticated Encryption | ChaCha20-Poly1305 (IETF RFC 8439) | 256-bit key / 128-bit MAC tag |
| Transcript Hashing | SHA-256 | 256-bit collision resistance |
| Integrity Checksum | IEEE 802.3 CRC32 | Frame error detection |

---

## 3. Vulnerability Reporting
To report security vulnerabilities, please reach out via encrypted whisper to node address `0x0000000000000001` or file an issue tagged `[SECURITY]`.
