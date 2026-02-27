# Beckn API — Payload Encryption & Decryption

## Overview

All Beckn API `message` bodies exchanged between Network Participants (NPs) are **fully encrypted**.

- The entire `message` body is encrypted as a single unit — no field is readable without decryption.
- The `context` block remains plaintext for network routing and audit.
- Any new field added to `message` in future is automatically encrypted with no additional implementation changes.

> **Note:** The receiver must decrypt the `message` before schema validation and ACK/NACK. This adds a small processing step on sync responses.

---

## Cryptographic Primitives

| Primitive | Role |
|---|---|
| X25519 / Diffie-Hellman | Shared secret derivation |
| AES-256-GCM | Symmetric payload encryption |
| Base64 | Binary-to-string encoding for JSON transport |

---

## Keys Involved

| Key | Held By | Purpose |
|---|---|---|
| `NP1_enc_private_key` | NP1 | Shared key derivation |
| `NP2_enc_public_key` | Registry | Shared key derivation (fetched by NP1) |
| `NP2_enc_private_key` | NP2 | Shared key derivation |
| `NP1_enc_public_key` | Registry | Shared key derivation (fetched by NP2) |

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

### Step 2 · Encrypt Message Body

```
serialized = JSON.stringify(messageBody)

iv = randomBytes(12)                          // fresh IV per API call

{ ciphertext, authTag } = AES_GCM.encrypt(
    plaintext = serialized,
    key       = sharedKey,
    iv        = iv
)

encrypted_message = Base64.encode(iv + ciphertext + authTag)
```

### Step 3 · Send API Request

```json
{
    "context": {
        "domain": "ONDC:FIS13",
        "country": "IND",
        "city": "std:080",
        "action": "confirm",
        "core_version": "2.1.0",
        "bap_id": "buyer-app.ondc.org",
        "bap_uri": "https://buyer-app.ondc.org/protocol/v1",
        "bpp_id": "seller-app.ondc.org",
        "bpp_uri": "https://seller-app.ondc.org/protocol/v1",
        "transaction_id": "123e4567-e89b-12d3-a456-426614174000",
        "message_id": "123e4567-e89b-12d3-a456-426614174001",
        "timestamp": "2024-03-23T18:25:43.511Z"
    },
    "message": "<Base64( iv + ciphertext + authTag )>"
}
```

> `context` is always plaintext. `message` carries the fully encrypted Beckn body.

---

## NP2 — Receiver Side

### Step 4 · Derive Shared Key

```
np1_enc_public_key = registry.fetchEncryptionPublicKey(np1_id)

sharedKey = DiffieHellman(
    privateKey = NP2_enc_private_key,
    publicKey  = np1_enc_public_key
)
```

### Step 5 · Decrypt Message Body

```
rawBytes = Base64.decode(encrypted_message)

iv         = rawBytes[0:12]
authTag    = rawBytes[-16:]
ciphertext = rawBytes[12:-16]

TRY:
    decrypted = AES_GCM.decrypt(
        ciphertext = ciphertext,
        key        = sharedKey,
        iv         = iv,
        authTag    = authTag       // integrity verified automatically
    )
    messageBody = JSON.parse(decrypted)

CATCH IntegrityError  → NACK("Payload integrity check failed")
CATCH DecryptionError → NACK("Decryption failed — key mismatch or malformed payload")
```

### Step 6 · Validate Schema & Respond

```
if NOT schema.validate(context.action, messageBody):
    → NACK("Schema validation failed")

processAction(context.action, messageBody)
→ ACK()
```

---

## End-to-End Flow

```
NP1 (Sender)                                    NP2 (Receiver)
─────────────────────────────────────────────────────────────────
1. Fetch NP2 enc public key (registry)
2. Derive sharedKey via DiffieHellman
3. JSON.stringify(messageBody)
4. Generate random IV (12 bytes)
5. AES_GCM.encrypt → Base64 encode
6. POST { context (plaintext), message (encrypted) }
                                                7.  Fetch NP1 enc public key (registry)
                                                8.  Derive sharedKey via DiffieHellman
                                                9.  Base64.decode → split iv / ciphertext / authTag
                                                10. AES_GCM.decrypt → verify authTag
                                                11. JSON.parse → messageBody
                                                12. schema.validate → ACK or NACK
                                                13. processAction
```
