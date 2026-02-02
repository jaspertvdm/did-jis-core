# did-jis-core

**Decentralized Identifiers for JTel Identity Standard**

The identity layer for HumoticaOS. Pairs with [tibet-core](https://pypi.org/project/tibet-core/) for complete AI provenance.

## Install

```bash
pip install did-jis-core    # Python
npm install did-jis-core    # JavaScript (coming soon)
```

## Quick Start

```python
from did_jis_core import DIDEngine, DIDDocumentBuilder

# Create identity engine with Ed25519 keypair
engine = DIDEngine()
print(f"Public key: {engine.public_key}")

# Create a DID
did = engine.create_did("alice")
# -> "did:jis:alice"

# Or create from public key hash
did = engine.create_did_from_key()
# -> "did:jis:a1b2c3d4e5f6..."

# Build a DID Document
builder = DIDDocumentBuilder(did)
builder.add_verification_method("key-1", engine.public_key)
builder.add_authentication("key-1")
builder.add_consent_service("https://api.example.com/consent")
builder.add_tibet_service("https://api.example.com/tibet")
doc_json = builder.build()

# Sign and verify
message = "Hello, DID!"
signature = engine.sign(message)
valid = engine.verify(message, signature)  # True

# Verify with external key
valid = DIDEngine.verify_with_key(message, signature, engine.public_key)
```

## With tibet-core

```python
from did_jis_core import DIDEngine
from tibet_core import TibetEngine

# Create identities
did_engine = DIDEngine()
tibet_engine = TibetEngine()

# Create DID
did = did_engine.create_did("my-agent")

# Create provenance token with DID as actor
token = tibet_engine.create_token(
    "action",
    "Processed user request",
    ["input-token-123"],
    '{"model": "gpt-4"}',
    "User asked for help",
    did  # actor is the DID
)
```

## API

### DIDEngine

| Method | Description |
|--------|-------------|
| `DIDEngine()` | Create new engine with fresh Ed25519 keypair |
| `DIDEngine.from_secret_key(hex)` | Create from existing secret key |
| `.public_key` | Get public key as hex string |
| `.public_key_multibase` | Get public key in multibase format |
| `.create_did(id)` | Create did:jis:id |
| `.create_did_from_key()` | Create DID from public key hash |
| `.sign(message)` | Sign message, return hex signature |
| `.verify(message, signature)` | Verify signature |
| `.create_document(did)` | Create signed DID document |

### DIDDocumentBuilder

| Method | Description |
|--------|-------------|
| `DIDDocumentBuilder(did)` | Create builder for DID |
| `.set_controller(did)` | Set document controller |
| `.add_verification_method(id, pubkey)` | Add Ed25519 verification method |
| `.add_authentication(key_id)` | Add authentication reference |
| `.add_assertion_method(key_id)` | Add assertion method reference |
| `.add_service(id, type, endpoint)` | Add service endpoint |
| `.add_consent_service(endpoint)` | Add bilateral consent service |
| `.add_tibet_service(endpoint)` | Add TIBET provenance service |
| `.build()` | Build and return JSON document |

### Functions

| Function | Description |
|----------|-------------|
| `parse_did_py(did)` | Parse DID into (method, id) tuple |
| `is_valid_did_py(did)` | Check if did:jis is valid |
| `create_did_py(parts)` | Create did:jis from parts list |

## The Stack

```
did:jis  → WHO (identity, keys, resolution)
tibet    → WHAT + WHEN + WHY (provenance, audit)
```

Together they provide complete AI provenance for 6G networks.

## Links

- **PyPI**: https://pypi.org/project/did-jis-core/
- **npm**: https://www.npmjs.com/package/did-jis-core
- **GitHub**: https://github.com/jaspertvdm/did-jis-core
- **IETF Draft**: https://datatracker.ietf.org/doc/draft-vandemeent-jis-identity/

## License

MIT OR Apache-2.0

---
*Co-created by Jasper van de Meent & Root AI*
