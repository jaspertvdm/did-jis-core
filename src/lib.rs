//! DID:JIS - Decentralized Identifiers for JTel Identity Standard
//!
//! Part of the HumoticaOS identity stack.
//! IETF Draft: draft-vandemeent-jis-identity
//!
//! # Example
//!
//! ```rust
//! use did_jis_core::{DIDEngine, DIDDocumentBuilder};
//!
//! let engine = DIDEngine::new();
//! let did = engine.create_did("alice");
//!
//! let doc = DIDDocumentBuilder::new(&did)
//!     .add_verification_method_ed25519("key-1", engine.public_key_hex())
//!     .add_authentication("key-1")
//!     .build();
//! ```

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use alloc::vec;
use alloc::format;
use alloc::borrow::ToOwned;
use core::fmt;

use ed25519_dalek::{SigningKey, VerifyingKey, Signer, Verifier, Signature};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};

// ============================================
// DID Types
// ============================================

/// A parsed DID identifier
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ParsedDID {
    pub method: String,
    pub id: String,
}

/// Verification method types
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum VerificationMethodType {
    Ed25519VerificationKey2020,
    JsonWebKey2020,
    EcdsaSecp256k1VerificationKey2019,
}

impl fmt::Display for VerificationMethodType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ed25519VerificationKey2020 => write!(f, "Ed25519VerificationKey2020"),
            Self::JsonWebKey2020 => write!(f, "JsonWebKey2020"),
            Self::EcdsaSecp256k1VerificationKey2019 => write!(f, "EcdsaSecp256k1VerificationKey2019"),
        }
    }
}

/// A verification method in a DID document
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationMethod {
    pub id: String,
    #[serde(rename = "type")]
    pub method_type: String,
    pub controller: String,
    #[serde(rename = "publicKeyMultibase", skip_serializing_if = "Option::is_none")]
    pub public_key_multibase: Option<String>,
    #[serde(rename = "publicKeyHex", skip_serializing_if = "Option::is_none")]
    pub public_key_hex: Option<String>,
}

/// A service endpoint in a DID document
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceEndpoint {
    pub id: String,
    #[serde(rename = "type")]
    pub service_type: String,
    #[serde(rename = "serviceEndpoint")]
    pub endpoint: String,
}

/// A complete DID Document
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DIDDocument {
    #[serde(rename = "@context")]
    pub context: Vec<String>,
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub controller: Option<String>,
    #[serde(rename = "verificationMethod", skip_serializing_if = "Vec::is_empty", default)]
    pub verification_method: Vec<VerificationMethod>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub authentication: Vec<String>,
    #[serde(rename = "assertionMethod", skip_serializing_if = "Vec::is_empty", default)]
    pub assertion_method: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub service: Vec<ServiceEndpoint>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated: Option<String>,
}

// ============================================
// DID Parsing and Validation
// ============================================

/// Parse a DID string into its components
pub fn parse_did(did: &str) -> Option<ParsedDID> {
    if !did.starts_with("did:") {
        return None;
    }

    let parts: Vec<&str> = did.splitn(3, ':').collect();
    if parts.len() < 3 {
        return None;
    }

    Some(ParsedDID {
        method: parts[1].to_string(),
        id: parts[2].to_string(),
    })
}

/// Validate a did:jis identifier
pub fn is_valid_did(did: &str) -> bool {
    if !did.starts_with("did:jis:") {
        return false;
    }

    if let Some(parsed) = parse_did(did) {
        // ID must be non-empty and contain valid characters
        !parsed.id.is_empty() && parsed.id.chars().all(|c| {
            c.is_ascii_alphanumeric() || c == ':' || c == '.' || c == '_' || c == '-'
        })
    } else {
        false
    }
}

/// Create a did:jis identifier from parts
pub fn create_did(parts: &[&str]) -> Result<String, &'static str> {
    if parts.is_empty() {
        return Err("DID must have at least one identifier part");
    }

    let id = parts.join(":");

    // Validate characters
    if !id.chars().all(|c| c.is_ascii_alphanumeric() || c == ':' || c == '.' || c == '_' || c == '-') {
        return Err("DID contains invalid characters");
    }

    Ok(format!("did:jis:{}", id))
}

// ============================================
// DID Document Builder
// ============================================

/// Builder for DID Documents
pub struct DIDDocumentBuilder {
    doc: DIDDocument,
}

impl DIDDocumentBuilder {
    /// Create a new DID Document builder
    pub fn new(did: &str) -> Result<Self, &'static str> {
        if !is_valid_did(did) {
            return Err("Invalid DID");
        }

        let now = get_timestamp();

        Ok(Self {
            doc: DIDDocument {
                context: vec![
                    "https://www.w3.org/ns/did/v1".to_string(),
                    "https://w3id.org/security/suites/ed25519-2020/v1".to_string(),
                    "https://humotica.com/ns/jis/v1".to_string(),
                ],
                id: did.to_string(),
                controller: None,
                verification_method: Vec::new(),
                authentication: Vec::new(),
                assertion_method: Vec::new(),
                service: Vec::new(),
                created: Some(now.clone()),
                updated: Some(now),
            },
        })
    }

    /// Set the controller
    pub fn set_controller(mut self, controller: &str) -> Self {
        self.doc.controller = Some(controller.to_string());
        self
    }

    /// Add an Ed25519 verification method
    pub fn add_verification_method_ed25519(mut self, key_id: &str, public_key_hex: &str) -> Self {
        let full_id = format!("{}#{}", self.doc.id, key_id);

        self.doc.verification_method.push(VerificationMethod {
            id: full_id,
            method_type: VerificationMethodType::Ed25519VerificationKey2020.to_string(),
            controller: self.doc.id.clone(),
            public_key_multibase: None,
            public_key_hex: Some(public_key_hex.to_string()),
        });
        self
    }

    /// Add a verification method with multibase encoding
    pub fn add_verification_method_multibase(mut self, key_id: &str, method_type: VerificationMethodType, public_key_multibase: &str) -> Self {
        let full_id = format!("{}#{}", self.doc.id, key_id);

        self.doc.verification_method.push(VerificationMethod {
            id: full_id,
            method_type: method_type.to_string(),
            controller: self.doc.id.clone(),
            public_key_multibase: Some(public_key_multibase.to_string()),
            public_key_hex: None,
        });
        self
    }

    /// Add authentication method reference
    pub fn add_authentication(mut self, key_id: &str) -> Self {
        let full_id = format!("{}#{}", self.doc.id, key_id);
        self.doc.authentication.push(full_id);
        self
    }

    /// Add assertion method reference
    pub fn add_assertion_method(mut self, key_id: &str) -> Self {
        let full_id = format!("{}#{}", self.doc.id, key_id);
        self.doc.assertion_method.push(full_id);
        self
    }

    /// Add a service endpoint
    pub fn add_service(mut self, service_id: &str, service_type: &str, endpoint: &str) -> Self {
        let full_id = format!("{}#{}", self.doc.id, service_id);

        self.doc.service.push(ServiceEndpoint {
            id: full_id,
            service_type: service_type.to_string(),
            endpoint: endpoint.to_string(),
        });
        self
    }

    /// Add bilateral consent service
    pub fn add_consent_service(self, endpoint: &str) -> Self {
        self.add_service("bilateral-consent", "BilateralConsentService", endpoint)
    }

    /// Add TIBET provenance service
    pub fn add_tibet_service(self, endpoint: &str) -> Self {
        self.add_service("tibet-provenance", "TIBETProvenanceService", endpoint)
    }

    /// Build the DID document
    pub fn build(mut self) -> DIDDocument {
        self.doc.updated = Some(get_timestamp());
        self.doc
    }

    /// Build and return as JSON string
    #[cfg(feature = "std")]
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(&self.doc).unwrap_or_default()
    }
}

// ============================================
// DID Engine (with cryptography)
// ============================================

/// DID Engine with Ed25519 key management
pub struct DIDEngine {
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
}

impl DIDEngine {
    /// Create a new DID Engine with a fresh keypair
    pub fn new() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();

        Self {
            signing_key,
            verifying_key,
        }
    }

    /// Create from existing secret key bytes (32 bytes)
    pub fn from_secret_key(secret: &[u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(secret);
        let verifying_key = signing_key.verifying_key();

        Self {
            signing_key,
            verifying_key,
        }
    }

    /// Get the public key as hex string
    pub fn public_key_hex(&self) -> String {
        hex::encode(self.verifying_key.as_bytes())
    }

    /// Get the public key as multibase (z-base58btc prefix)
    pub fn public_key_multibase(&self) -> String {
        // Simple hex with 'f' prefix (multibase hex)
        format!("f{}", self.public_key_hex())
    }

    /// Create a new did:jis identifier
    pub fn create_did(&self, id: &str) -> String {
        format!("did:jis:{}", id)
    }

    /// Create a DID from the public key hash
    pub fn create_did_from_key(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.verifying_key.as_bytes());
        let hash = hasher.finalize();
        let short_hash = &hex::encode(hash)[..16]; // First 16 chars
        format!("did:jis:{}", short_hash)
    }

    /// Sign data and return hex-encoded signature
    pub fn sign(&self, data: &[u8]) -> String {
        let signature = self.signing_key.sign(data);
        hex::encode(signature.to_bytes())
    }

    /// Sign a string message
    pub fn sign_string(&self, message: &str) -> String {
        self.sign(message.as_bytes())
    }

    /// Verify a signature
    pub fn verify(&self, data: &[u8], signature_hex: &str) -> bool {
        let sig_bytes = match hex::decode(signature_hex) {
            Ok(b) => b,
            Err(_) => return false,
        };

        let signature = match Signature::from_slice(&sig_bytes) {
            Ok(s) => s,
            Err(_) => return false,
        };

        self.verifying_key.verify(data, &signature).is_ok()
    }

    /// Verify with a different public key
    pub fn verify_with_key(data: &[u8], signature_hex: &str, public_key_hex: &str) -> bool {
        let pub_bytes = match hex::decode(public_key_hex) {
            Ok(b) => b,
            Err(_) => return false,
        };

        let pub_key_bytes: [u8; 32] = match pub_bytes.try_into() {
            Ok(b) => b,
            Err(_) => return false,
        };

        let verifying_key = match VerifyingKey::from_bytes(&pub_key_bytes) {
            Ok(k) => k,
            Err(_) => return false,
        };

        let sig_bytes = match hex::decode(signature_hex) {
            Ok(b) => b,
            Err(_) => return false,
        };

        let signature = match Signature::from_slice(&sig_bytes) {
            Ok(s) => s,
            Err(_) => return false,
        };

        verifying_key.verify(data, &signature).is_ok()
    }

    /// Create a signed DID document
    #[cfg(feature = "std")]
    pub fn create_signed_document(&self, did: &str) -> Result<String, &'static str> {
        let doc = DIDDocumentBuilder::new(did)?
            .add_verification_method_ed25519("key-1", &self.public_key_hex())
            .add_authentication("key-1")
            .add_assertion_method("key-1")
            .build();

        let doc_json = serde_json::to_string(&doc).map_err(|_| "Serialization failed")?;
        let signature = self.sign_string(&doc_json);

        // Return document with proof
        let signed = serde_json::json!({
            "document": doc,
            "proof": {
                "type": "Ed25519Signature2020",
                "created": get_timestamp(),
                "verificationMethod": format!("{}#key-1", did),
                "proofPurpose": "assertionMethod",
                "proofValue": signature
            }
        });

        serde_json::to_string_pretty(&signed).map_err(|_| "Serialization failed")
    }
}

impl Default for DIDEngine {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================
// Timestamp helper
// ============================================

fn get_timestamp() -> String {
    chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

// ============================================
// Python Bindings
// ============================================

#[cfg(feature = "python")]
mod python {
    use super::*;
    use pyo3::prelude::*;
    use pyo3::types::PyModuleMethods;
    use pyo3::exceptions::PyValueError;
    use pyo3::Bound;

    #[pyclass(name = "DIDEngine")]
    pub struct PyDIDEngine {
        engine: DIDEngine,
    }

    #[pymethods]
    impl PyDIDEngine {
        #[new]
        fn new() -> Self {
            Self {
                engine: DIDEngine::new(),
            }
        }

        #[staticmethod]
        fn from_secret_key(secret_hex: &str) -> PyResult<Self> {
            let secret_bytes = hex::decode(secret_hex)
                .map_err(|_| PyValueError::new_err("Invalid hex string"))?;

            let secret: [u8; 32] = secret_bytes.try_into()
                .map_err(|_| PyValueError::new_err("Secret key must be 32 bytes"))?;

            Ok(Self {
                engine: DIDEngine::from_secret_key(&secret),
            })
        }

        #[getter]
        fn public_key(&self) -> String {
            self.engine.public_key_hex()
        }

        #[getter]
        fn public_key_multibase(&self) -> String {
            self.engine.public_key_multibase()
        }

        fn create_did(&self, id: &str) -> String {
            self.engine.create_did(id)
        }

        fn create_did_from_key(&self) -> String {
            self.engine.create_did_from_key()
        }

        fn sign(&self, message: &str) -> String {
            self.engine.sign_string(message)
        }

        fn verify(&self, message: &str, signature: &str) -> bool {
            self.engine.verify(message.as_bytes(), signature)
        }

        #[staticmethod]
        fn verify_with_key(message: &str, signature: &str, public_key: &str) -> bool {
            DIDEngine::verify_with_key(message.as_bytes(), signature, public_key)
        }

        fn create_document(&self, did: &str) -> PyResult<String> {
            self.engine.create_signed_document(did)
                .map_err(|e| PyValueError::new_err(e))
        }
    }

    #[pyclass(name = "DIDDocumentBuilder")]
    pub struct PyDIDDocumentBuilder {
        did: String,
        controller: Option<String>,
        verification_methods: Vec<(String, String)>, // (key_id, public_key_hex)
        authentication: Vec<String>,
        assertion_methods: Vec<String>,
        services: Vec<(String, String, String)>, // (id, type, endpoint)
    }

    #[pymethods]
    impl PyDIDDocumentBuilder {
        #[new]
        fn new(did: &str) -> PyResult<Self> {
            if !is_valid_did(did) {
                return Err(PyValueError::new_err("Invalid DID"));
            }

            Ok(Self {
                did: did.to_string(),
                controller: None,
                verification_methods: Vec::new(),
                authentication: Vec::new(),
                assertion_methods: Vec::new(),
                services: Vec::new(),
            })
        }

        fn set_controller(&mut self, controller: &str) -> PyResult<()> {
            self.controller = Some(controller.to_string());
            Ok(())
        }

        fn add_verification_method(&mut self, key_id: &str, public_key_hex: &str) -> PyResult<()> {
            self.verification_methods.push((key_id.to_string(), public_key_hex.to_string()));
            Ok(())
        }

        fn add_authentication(&mut self, key_id: &str) -> PyResult<()> {
            self.authentication.push(key_id.to_string());
            Ok(())
        }

        fn add_assertion_method(&mut self, key_id: &str) -> PyResult<()> {
            self.assertion_methods.push(key_id.to_string());
            Ok(())
        }

        fn add_service(&mut self, service_id: &str, service_type: &str, endpoint: &str) -> PyResult<()> {
            self.services.push((service_id.to_string(), service_type.to_string(), endpoint.to_string()));
            Ok(())
        }

        fn add_consent_service(&mut self, endpoint: &str) -> PyResult<()> {
            self.add_service("bilateral-consent", "BilateralConsentService", endpoint)
        }

        fn add_tibet_service(&mut self, endpoint: &str) -> PyResult<()> {
            self.add_service("tibet-provenance", "TIBETProvenanceService", endpoint)
        }

        fn build(&self) -> PyResult<String> {
            let mut builder = DIDDocumentBuilder::new(&self.did)
                .map_err(|e| PyValueError::new_err(e))?;

            if let Some(ref controller) = self.controller {
                builder = builder.set_controller(controller);
            }

            for (key_id, public_key) in &self.verification_methods {
                builder = builder.add_verification_method_ed25519(key_id, public_key);
            }

            for key_id in &self.authentication {
                builder = builder.add_authentication(key_id);
            }

            for key_id in &self.assertion_methods {
                builder = builder.add_assertion_method(key_id);
            }

            for (service_id, service_type, endpoint) in &self.services {
                builder = builder.add_service(service_id, service_type, endpoint);
            }

            Ok(builder.to_json())
        }
    }

    /// Parse a DID string
    #[pyfunction]
    fn parse_did_py(did: &str) -> PyResult<Option<(String, String)>> {
        Ok(parse_did(did).map(|p| (p.method, p.id)))
    }

    /// Validate a did:jis identifier
    #[pyfunction]
    fn is_valid_did_py(did: &str) -> bool {
        is_valid_did(did)
    }

    /// Create a did:jis identifier
    #[pyfunction]
    fn create_did_py(parts: Vec<String>) -> PyResult<String> {
        let parts_ref: Vec<&str> = parts.iter().map(|s| s.as_str()).collect();
        create_did(&parts_ref).map_err(|e| PyValueError::new_err(e))
    }

    #[pymodule]
    fn did_jis_core(m: &Bound<'_, pyo3::types::PyModule>) -> PyResult<()> {
        m.add_class::<PyDIDEngine>()?;
        m.add_class::<PyDIDDocumentBuilder>()?;
        m.add_function(wrap_pyfunction!(parse_did_py, m)?)?;
        m.add_function(wrap_pyfunction!(is_valid_did_py, m)?)?;
        m.add_function(wrap_pyfunction!(create_did_py, m)?)?;
        m.add("__version__", "0.1.0")?;
        Ok(())
    }
}

// ============================================
// WASM Bindings
// ============================================

#[cfg(feature = "wasm")]
mod wasm {
    use super::*;
    use wasm_bindgen::prelude::*;

    #[wasm_bindgen]
    pub struct WasmDIDEngine {
        engine: DIDEngine,
    }

    #[wasm_bindgen]
    impl WasmDIDEngine {
        #[wasm_bindgen(constructor)]
        pub fn new() -> Self {
            Self {
                engine: DIDEngine::new(),
            }
        }

        #[wasm_bindgen(js_name = fromSecretKey)]
        pub fn from_secret_key(secret_hex: &str) -> Result<WasmDIDEngine, JsValue> {
            let secret_bytes = hex::decode(secret_hex)
                .map_err(|_| JsValue::from_str("Invalid hex string"))?;

            let secret: [u8; 32] = secret_bytes.try_into()
                .map_err(|_| JsValue::from_str("Secret key must be 32 bytes"))?;

            Ok(Self {
                engine: DIDEngine::from_secret_key(&secret),
            })
        }

        #[wasm_bindgen(getter, js_name = publicKey)]
        pub fn public_key(&self) -> String {
            self.engine.public_key_hex()
        }

        #[wasm_bindgen(getter, js_name = publicKeyMultibase)]
        pub fn public_key_multibase(&self) -> String {
            self.engine.public_key_multibase()
        }

        #[wasm_bindgen(js_name = createDid)]
        pub fn create_did(&self, id: &str) -> String {
            self.engine.create_did(id)
        }

        #[wasm_bindgen(js_name = createDidFromKey)]
        pub fn create_did_from_key(&self) -> String {
            self.engine.create_did_from_key()
        }

        pub fn sign(&self, message: &str) -> String {
            self.engine.sign_string(message)
        }

        pub fn verify(&self, message: &str, signature: &str) -> bool {
            self.engine.verify(message.as_bytes(), signature)
        }

        #[wasm_bindgen(js_name = verifyWithKey)]
        pub fn verify_with_key(message: &str, signature: &str, public_key: &str) -> bool {
            DIDEngine::verify_with_key(message.as_bytes(), signature, public_key)
        }

        #[wasm_bindgen(js_name = createDocument)]
        pub fn create_document(&self, did: &str) -> Result<String, JsValue> {
            self.engine.create_signed_document(did)
                .map_err(|e| JsValue::from_str(e))
        }
    }

    /// Parse a DID string
    #[wasm_bindgen(js_name = parseDid)]
    pub fn parse_did_wasm(did: &str) -> JsValue {
        match parse_did(did) {
            Some(parsed) => {
                ::serde_wasm_bindgen::to_value(&parsed).unwrap_or(JsValue::NULL)
            }
            None => JsValue::NULL,
        }
    }

    /// Validate a did:jis identifier
    #[wasm_bindgen(js_name = isValidDid)]
    pub fn is_valid_did_wasm(did: &str) -> bool {
        is_valid_did(did)
    }

    /// Create a did:jis identifier
    #[wasm_bindgen(js_name = createDid)]
    pub fn create_did_wasm(parts: Vec<String>) -> Result<String, JsValue> {
        let parts_ref: Vec<&str> = parts.iter().map(|s| s.as_str()).collect();
        create_did(&parts_ref).map_err(|e| JsValue::from_str(e))
    }
}

// ============================================
// Tests
// ============================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_did() {
        let parsed = parse_did("did:jis:alice").unwrap();
        assert_eq!(parsed.method, "jis");
        assert_eq!(parsed.id, "alice");

        let parsed2 = parse_did("did:jis:org:company:employee").unwrap();
        assert_eq!(parsed2.id, "org:company:employee");

        assert!(parse_did("invalid").is_none());
    }

    #[test]
    fn test_is_valid_did() {
        assert!(is_valid_did("did:jis:alice"));
        assert!(is_valid_did("did:jis:org:company:employee42"));
        assert!(!is_valid_did("did:web:example.com"));
        assert!(!is_valid_did("invalid"));
    }

    #[test]
    fn test_create_did() {
        assert_eq!(create_did(&["alice"]).unwrap(), "did:jis:alice");
        assert_eq!(create_did(&["org", "company", "42"]).unwrap(), "did:jis:org:company:42");
    }

    #[test]
    fn test_did_engine() {
        let engine = DIDEngine::new();

        // Check public key is valid hex
        let pk = engine.public_key_hex();
        assert_eq!(pk.len(), 64); // 32 bytes = 64 hex chars

        // Test signing and verification
        let message = "Hello, DID!";
        let signature = engine.sign_string(message);
        assert!(engine.verify(message.as_bytes(), &signature));

        // Wrong message should fail
        assert!(!engine.verify(b"Wrong message", &signature));
    }

    #[test]
    fn test_did_document_builder() {
        let engine = DIDEngine::new();
        let did = "did:jis:alice";

        let doc = DIDDocumentBuilder::new(did).unwrap()
            .add_verification_method_ed25519("key-1", &engine.public_key_hex())
            .add_authentication("key-1")
            .add_consent_service("https://api.example.com/consent")
            .build();

        assert_eq!(doc.id, did);
        assert_eq!(doc.verification_method.len(), 1);
        assert_eq!(doc.authentication.len(), 1);
        assert_eq!(doc.service.len(), 1);
    }
}
