#!/usr/bin/env python3

import hashlib
import hmac
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend

def derive_protocol_shared_secret(ecdh_result):
    """
    Derive shared secret for CTAP2 PIN Protocol 2 using HKDF.
    Returns 64 bytes: 32 bytes HMAC key + 32 bytes AES key
    """
    shared_secret = bytearray()

    # HMAC key: HKDF-SHA-256(salt=32 zeros, IKM=Z, L=32, info="CTAP2 HMAC key")
    hkdf_salt = b'\x00' * 32
    hmac_key_info = b'CTAP2 HMAC key'

    hkdf_hmac = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=hkdf_salt,
        info=hmac_key_info,
        backend=default_backend()
    )
    hmac_key_material = hkdf_hmac.derive(ecdh_result)
    shared_secret.extend(hmac_key_material)

    # AES key: HKDF-SHA-256(salt=32 zeros, IKM=Z, L=32, info="CTAP2 AES key")
    aes_key_info = b'CTAP2 AES key'

    hkdf_aes = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=hkdf_salt,
        info=aes_key_info,
        backend=default_backend()
    )
    aes_key_material = hkdf_aes.derive(ecdh_result)
    shared_secret.extend(aes_key_material)

    return bytes(shared_secret)

def generate_test_values():
    """Generate test values for CTAP PIN Protocol 2"""

    # Example ECDH result (this would normally come from actual ECDH computation)
    # Using a known test vector for reproducible results
    example_ecdh_result = bytes([
        0x87, 0x6e, 0x3d, 0x99, 0x2c, 0x5a, 0x1b, 0x84,
        0x6f, 0x2d, 0x87, 0x62, 0xaa, 0x38, 0x92, 0x7c,
        0x4e, 0x5c, 0x3b, 0x23, 0x1d, 0xe6, 0x89, 0x45,
        0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0
    ])

    # Derive the shared secret using HKDF
    shared_secret = derive_protocol_shared_secret(example_ecdh_result)

    print("// Generated test values for CTAP PIN Protocol 2")
    print("// ECDH result (input):")
    print("constexpr std::array<uint8_t, 32> testECDHResult {")
    print("    " + ", ".join(f"0x{b:02x}" for b in example_ecdh_result[:16]) + ",")
    print("    " + ", ".join(f"0x{b:02x}" for b in example_ecdh_result[16:32]))
    print("};")
    print()

    print("// Expected shared secret (64 bytes: 32 HMAC + 32 AES):")
    print("constexpr std::array<uint8_t, 64> expectedSharedSecret {")
    for i in range(0, 64, 16):
        chunk = shared_secret[i:i+16]
        print("    " + ", ".join(f"0x{b:02x}" for b in chunk) + ("," if i < 48 else ""))
    print("};")
    print()

    # Split into HMAC and AES portions for clarity
    hmac_key = shared_secret[:32]
    aes_key = shared_secret[32:64]

    print("// HMAC key portion (first 32 bytes):")
    print("constexpr std::array<uint8_t, 32> expectedHMACKey {")
    print("    " + ", ".join(f"0x{b:02x}" for b in hmac_key[:16]) + ",")
    print("    " + ", ".join(f"0x{b:02x}" for b in hmac_key[16:32]))
    print("};")
    print()

    print("// AES key portion (last 32 bytes):")
    print("constexpr std::array<uint8_t, 32> expectedAESKey {")
    print("    " + ", ".join(f"0x{b:02x}" for b in aes_key[:16]) + ",")
    print("    " + ", ".join(f"0x{b:02x}" for b in aes_key[16:32]))
    print("};")

if __name__ == "__main__":
    generate_test_values()