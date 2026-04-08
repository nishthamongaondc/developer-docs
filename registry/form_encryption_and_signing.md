# Form Submission — Encryption, Decryption & Signing

## Overview

All form payloads submitted between Network Participants (NPs) are **fully encrypted and signed**.

- The entire form body is encrypted — no individual field is readable in transit.
- A signature over the encrypted payload ensures authenticity and tamper detection.
- The receiver can decrypt and validate the form independently.

---

## Cryptographic Primitives

| Primitive | Role |
|---|---|
| X25519 / Diffie-Hellman | Shared secret derivation |
| AES-256-GCM | Symmetric payload encryption |
| Ed25519 | Payload signing & verification |
| BLAKE-512 | Digest generation before signing |
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

Signing follows the same method used for Beckn API request signing (see [ONDC Network Signing & Verifying](./signing-verification.md)).

**3a. Generate the digest** of the `encrypted_payload` using BLAKE-512:

```
digest = Base64.encode( BLAKE512( encrypted_payload ) )
```

**3b. Construct the signing string** using `created`, `expires`, and the digest:

```
signing_string = "(created): {created_unix_ts}\n(expires): {expires_unix_ts}\ndigest:BLAKE-512={digest}"
```

**3c. Sign the signing string** using the NP's Ed25519 signing private key:

```
signature = Ed25519.sign(
    data       = signing_string,
    privateKey = NP1_sign_private_key
)

encoded_signature = Base64.encode(signature)
```

**3d. Set the Authorization header:**

```
Authorization: Signature
  keyId="{subscriber_id}|{unique_key_id}|ed25519",
  algorithm="ed25519",
  created="{created_unix_ts}",
  expires="{expires_unix_ts}",
  headers="(created) (expires) digest",
  signature="{encoded_signature}"
```

> For a worked example of key generation, digest computation, and Authorization header construction, refer to [ONDC Network Signing & Verifying](./signing-verification.md#authorization-header).

### Step 4 · Submit Form

Include the full `context` as plaintext, the `encrypted_payload`, and the `Authorization` header carrying the signature:

**Request Body:**

```json
{
  "context": {
    "action": "search",
    "bap_id": "fis.test.bap.io",
    "bap_uri": "https://fis.test.bap.io/",
    "domain": "ONDC:FIS13",
    "location": {
      "country": {
        "code": "IND"
      },
      "city": {
        "code": "*"
      }
    },
    "message_id": "385e3fb7-61e6-49a7-acbc-8ac05f934d4d",
    "timestamp": "2023-07-24T05:39:31.700Z",
    "transaction_id": "c04a04ee-d892-400f-bbe6-479a43b4448a",
    "ttl": "PT24H",
    "version": "2.0.1"
  },
  "encrypted_payload": "<Base64( iv + ciphertext + authTag )>"
}
```

**Authorization Header:**

```
Signature keyId="buyer-app.ondc.org|207|ed25519",algorithm="ed25519",created="1641287875",expires="1641291475",headers="(created) (expires) digest",signature="fKQWvXhln4UdyZdL87ViXQObdBme0dHnsclD2LvvnHoNxIgcvAwUZOmwAnH5QKi9Upg5tRaxpoGhCFGHD+d+Bw=="
```

> `context` is always plaintext. `encrypted_payload` carries the secured form data. The signature travels in the `Authorization` header, not in the request body.

---

## NP2 — Receiver Side

### Step 5 · Verify Signature

```
np1_sign_public_key = registry.fetchSigningPublicKey(np1_id)

// Extract fields from the Authorization header
auth        = parseAuthorizationHeader(request.headers["Authorization"])
created     = auth.created
expires     = auth.expires
signature   = auth.signature

digest = Base64.encode( BLAKE512( encrypted_payload ) )

signing_string = "(created): {created}\n(expires): {expires}\ndigest:BLAKE-512={digest}"

isValid = Ed25519.verify(
    data      = signing_string,
    signature = Base64.decode(signature),
    publicKey = np1_sign_public_key
)

if NOT isValid → REJECT("Signature verification failed")
```

> Always verify signature **before** decrypting.

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
6. BLAKE512(encrypted_payload) → construct signing string
7. Ed25519.sign → Base64 encode → Authorization header
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
