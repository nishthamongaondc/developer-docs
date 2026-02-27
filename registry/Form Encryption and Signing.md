# Form Submission — Encryption, Decryption & Signing

## Overview

All form payloads submitted between Network Participants (NPs) are **fully encrypted and signed**.

- The entire form body is encrypted — no individual field is readable in transit.
- A signature over the encrypted payload ensures authenticity and tamper detection.
- The signature hash can also be computed from `formData` text (for example, the output of `JSON.stringify(formData)`) if both NPs use the exact same format.
- The receiver can decrypt and validate the form independently.

---

## Cryptographic Primitives

| Primitive | Role |
|---|---|
| X25519 / Diffie-Hellman | Shared secret derivation |
| AES-256-GCM | Symmetric payload encryption |
| Ed25519 | Payload signing & verification |
| SHA-256 | Hashing before signing |
| Base64 | Binary-to-string encoding for transport |

---

## Keys Involved

| Key | Held By | Purpose |
|---|---|---|
| `NP1_enc_private_key` | NP1 | Shared key derivation |
| `NP2_enc_public_key` | Registry | Shared key derivation (fetched by NP1) |
| `NP1_sign_private_key` | NP1 | Signing the encrypted payload |
| `NP1_sign_public_key` | Registry | Signature verification (fetched by NP2) |

---

## NP1 — Sender Side

### Step 1 · Derive Shared Key

```
np2_enc_public_key = registry.fetchEncryptionPublicKey(np2_id)

sharedKey = DiffieHellman(
    privateKey = NP1_enc_private_key,
    publicKey  = np2_enc_public_key
)
```

### Step 2 · Encrypt Form Payload

```
serialized = JSON.stringify(formData)

iv = randomBytes(12)                          // fresh IV per submission

{ ciphertext, authTag } = AES_GCM.encrypt(
    plaintext = serialized,
    key       = sharedKey,
    iv        = iv
)

encrypted_payload = Base64.encode(iv + ciphertext + authTag)
```

### Step 3 · Sign Encrypted Payload

```
hash = SHA256(encrypted_payload)

signature = Ed25519.sign(
    data       = hash,
    privateKey = NP1_sign_private_key
)

encoded_signature = Base64.encode(signature)
```

> Alternate hashing input (if agreed): `hash = SHA256(JSON.stringify(formData))`.  
> In this mode, both sender and receiver must hash the exact same form-data text format.

### Step 4 · Submit Form

```json
{
  "context": {
    "np_id": "buyer-app.ondc.org",
    "transaction_id": "123e4567-e89b-12d3-a456-426614174000",
    "timestamp": "2024-03-23T18:25:43.511Z"
  },
  "encrypted_payload": "<Base64( iv + ciphertext + authTag )>",
  "signature": "<Base64( Ed25519 signature )>"
}
```

> `context` is always plaintext. `encrypted_payload` and `signature` carry the secured form data.

---

## NP2 — Receiver Side

### Step 5 · Verify Signature

```
np1_sign_public_key = registry.fetchSigningPublicKey(np1_id)

hash = SHA256(encrypted_payload)

isValid = Ed25519.verify(
    data      = hash,
    signature = Base64.decode(signature),
    publicKey = np1_sign_public_key
)

if NOT isValid → REJECT("Signature verification failed")
```

> Always verify signature **before** decrypting.
> If payload-hash signing is used, compute the hash from the same `JSON.stringify(formData)` output as the sender.

### Step 6 · Derive Shared Key

```
np1_enc_public_key = registry.fetchEncryptionPublicKey(np1_id)

sharedKey = DiffieHellman(
    privateKey = NP2_enc_private_key,
    publicKey  = np1_enc_public_key
)
```

### Step 7 · Decrypt Form Payload

```
rawBytes = Base64.decode(encrypted_payload)

iv         = rawBytes[0:12]
authTag    = rawBytes[-16:]
ciphertext = rawBytes[12:-16]

decrypted = AES_GCM.decrypt(
    ciphertext = ciphertext,
    key        = sharedKey,
    iv         = iv,
    authTag    = authTag       // integrity verified automatically
)

formData = JSON.parse(decrypted)
```

### Step 8 · Validate & Process

```
validate(formData)
preProcess(formData)
```

---

## End-to-End Flow

```
NP1 (Sender)                                    NP2 (Receiver)
─────────────────────────────────────────────────────────────────
1. Fetch NP2 enc public key (registry)
2. Derive sharedKey via DiffieHellman
3. JSON.stringify(formData)
4. Generate random IV (12 bytes)
5. AES_GCM.encrypt → Base64 encode
6. SHA256(encrypted_payload)
7. Ed25519.sign → Base64 encode
8. POST { context, encrypted_payload, signature }
                                                9.  Fetch NP1 sign public key (registry)
                                                10. Ed25519.verify → REJECT if invalid
                                                11. Fetch NP1 enc public key (registry)
                                                12. Derive sharedKey via DiffieHellman
                                                13. Base64.decode → split iv / ciphertext / authTag
                                                14. AES_GCM.decrypt → verify authTag
                                                15. JSON.parse → formData
                                                16. validate & preProcess
```
