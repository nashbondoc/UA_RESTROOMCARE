import os
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def demonstrate_ecc_aes_gcm():
    print("=" * 60)
    print(" UA RESTROOMCARE - CRYPTOGRAPHIC DEMONSTRATION")
    print(" ECC (ECDH) Key Exchange + AES-256-GCM Encryption")
    print("=" * 60)

    # 1. Generate ECC Key Pairs (SECP256R1 / NIST P-256)
    print("\n[Step 1] Generating ECC Key Pairs...")
    client_private_key = ec.generate_private_key(ec.SECP256R1())
    client_public_key = client_private_key.public_key()

    server_private_key = ec.generate_private_key(ec.SECP256R1())
    server_public_key = server_private_key.public_key()
    print(" -> Client and Server ECC Public/Private keypairs generated successfully.")

    # 2. Key Exchange (ECDH Derived Shared Secret)
    print("\n[Step 2] Executing Key Exchange (ECDH)...")
    client_shared_secret = client_private_key.exchange(ec.ECDH(), server_public_key)
    server_shared_secret = server_private_key.exchange(ec.ECDH(), client_public_key)

    assert client_shared_secret == server_shared_secret, "Shared secrets do not match!"
    print(" -> Shared secrets match on both ends.")

    # 3. Derive AES Encryption Key using HKDF
    print("\n[Step 3] Deriving Symmetric Key via HKDF...")
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'restroomcare report payload',
    )
    aes_key = hkdf.derive(client_shared_secret)
    print(f" -> Derived 256-bit AES Key: {aes_key.hex()[:16]}...[TRUNCATED]")

    # 4. Encrypt Payload using AES-256-GCM
    print("\n[Step 4] Encrypting Restroom Report Data...")
    original_data = b"CONFIDENTIAL REPORT: Damaged Lock in Main Hallway Restroom. User ID: 1042."
    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12) # 96-bit initialization vector
    ciphertext = aesgcm.encrypt(nonce, original_data, None)
    
    print(f" -> Original Data : {original_data.decode()}")
    print(f" -> Ciphertext    : {ciphertext.hex()}")
    print(f" -> Nonce (IV)    : {nonce.hex()}")

    # 5. Decrypt and Verify Payload Integrity
    print("\n[Step 5] Decrypting and Verifying Authenticity...")
    decrypted_data = aesgcm.decrypt(nonce, ciphertext, None)
    print(f" -> Decrypted Data: {decrypted_data.decode()}")
    assert decrypted_data == original_data, "Decrypted data does not match original payload!"
    print(" -> Verification Successful! Authenticity verified.")

    # 6. Tamper Detection Test
    print("\n[Step 6] Testing Unauthorized Data Tampering Detection...")
    tampered_ciphertext = bytearray(ciphertext)
    tampered_ciphertext[0] ^= 0xFF # Flip bits in ciphertext
    
    try:
        aesgcm.decrypt(nonce, bytes(tampered_ciphertext), None)
        print(" -> ERROR: Tampered payload was accepted!")
    except Exception as e:
        print(f" -> ALERT DETECTED: Tampered ciphertext rejected successfully! ({type(e).__name__})")

    print("\n" + "=" * 60)
    print(" DEMONSTRATION COMPLETE: Cryptographic Safeguards Verified.")
    print("=" * 60)

if __name__ == "__main__":
    demonstrate_ecc_aes_gcm()