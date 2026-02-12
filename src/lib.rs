use wasm_bindgen::prelude::*;
use ml_kem::{MlKem768, MlKem768Params, MlKem1024, MlKem1024Params, KemCore, Encoded, EncodedSizeUser};
use ml_kem::kem::{EncapsulationKey, DecapsulationKey, Encapsulate, Decapsulate};
use ml_dsa::{MlDsa44, MlDsa65, MlDsa87, KeyGen, SigningKey, VerifyingKey, Signature, EncodedSigningKey, EncodedVerifyingKey, EncodedSignature};
use ml_dsa::signature::{Signer, Verifier};
use rand_core::OsRng;
use ml_kem::Ciphertext as KemCiphertext;
use argon2::{Argon2, PasswordHasher, PasswordVerifier};
use argon2::password_hash::phc::PasswordHash;

// ──────────────────────────────────────────────────────────────
// Data structures exposed to JavaScript
// ──────────────────────────────────────────────────────────────

/// Key pair for ML-KEM (post-quantum KEM)
#[wasm_bindgen]
pub struct KemKeyPair {
    public_key: Vec<u8>,
    secret_key: Vec<u8>,
}

#[wasm_bindgen]
impl KemKeyPair {
    /// Returns a copy of the ML-KEM public key (encapsulation key) as bytes
    #[wasm_bindgen(getter)]
    pub fn public_key(&self) -> Vec<u8> {
        self.public_key.clone()
    }

    /// Returns a copy of the ML-KEM secret key (decapsulation key) as bytes
    #[wasm_bindgen(getter)]
    pub fn secret_key(&self) -> Vec<u8> {
        self.secret_key.clone()
    }
}

/// Key pair for ML-DSA (post-quantum digital signature scheme)
#[wasm_bindgen]
pub struct DsaKeyPair {
    public_key: Vec<u8>,
    secret_key: Vec<u8>,
}

#[wasm_bindgen]
impl DsaKeyPair {
    /// Returns a copy of the ML-DSA verifying (public) key as bytes
    #[wasm_bindgen(getter)]
    pub fn public_key(&self) -> Vec<u8> {
        self.public_key.clone()
    }

    /// Returns a copy of the ML-DSA signing (secret) key as bytes
    #[wasm_bindgen(getter)]
    pub fn secret_key(&self) -> Vec<u8> {
        self.secret_key.clone()
    }
}

/// Container for ML-KEM ciphertext + derived shared secret
#[wasm_bindgen]
pub struct CiphertextAndSharedSecret {
    ciphertext: Vec<u8>,
    shared_secret: Vec<u8>,
}

#[wasm_bindgen]
impl CiphertextAndSharedSecret {
    /// Returns a copy of the ML-KEM ciphertext
    #[wasm_bindgen(getter)]
    pub fn ciphertext(&self) -> Vec<u8> {
        self.ciphertext.clone()
    }

    /// Returns a copy of the 32-byte shared secret derived from encapsulation
    #[wasm_bindgen(getter)]
    pub fn shared_secret(&self) -> Vec<u8> {
        self.shared_secret.clone()
    }
}

// ──────────────────────────────────────────────────────────────
// ML-KEM-768 (Kyber-768 equivalent)
// ──────────────────────────────────────────────────────────────

/// Generates a fresh ML-KEM-768 key pair using OS RNG.
///
/// Returns: `KemKeyPair` containing public & secret key bytes.
#[wasm_bindgen]
pub fn ml_kem_768_generate_keypair() -> Result<KemKeyPair, JsValue> {
    let (sk, pk) = MlKem768::generate(&mut OsRng);
    Ok(KemKeyPair {
        public_key: pk.as_bytes().to_vec(),
        secret_key: sk.as_bytes().to_vec(),
    })
}

/// Performs ML-KEM-768 encapsulation using the provided public key.
///
/// # Arguments
/// * `public_key_bytes` - Encoded ML-KEM-768 encapsulation key (1184 bytes)
///
/// Returns: ciphertext + 32-byte shared secret
#[wasm_bindgen]
pub fn ml_kem_768_encapsulate(public_key_bytes: &[u8]) -> Result<CiphertextAndSharedSecret, JsValue> {
    let enc_pk: Encoded<EncapsulationKey<MlKem768Params>> = public_key_bytes
        .try_into()
        .map_err(|_| JsValue::from_str("Invalid public key length"))?;
    let pk = EncapsulationKey::<MlKem768Params>::from_bytes(&enc_pk);

    let (ct, ss) = pk.encapsulate(&mut OsRng).map_err(|_| JsValue::from_str("Encapsulation failed"))?;

    Ok(CiphertextAndSharedSecret {
        ciphertext: ct.to_vec(),
        shared_secret: ss.to_vec(),
    })
}

/// Performs ML-KEM-768 decapsulation to recover the shared secret.
///
/// # Arguments
/// * `secret_key_bytes`  – Encoded ML-KEM-768 decapsulation key (2400 bytes)
/// * `ciphertext_bytes`  – ML-KEM-768 ciphertext (1088 bytes)
///
/// Returns: 32-byte shared secret (or error)
#[wasm_bindgen]
pub fn ml_kem_768_decapsulate(secret_key_bytes: &[u8], ciphertext_bytes: &[u8]) -> Result<Vec<u8>, JsValue> {
    let enc_sk: Encoded<DecapsulationKey<MlKem768Params>> = secret_key_bytes
        .try_into()
        .map_err(|_| JsValue::from_str("Invalid secret key length"))?;
    let sk = DecapsulationKey::<MlKem768Params>::from_bytes(&enc_sk);

    let ct: KemCiphertext<MlKem768> = ciphertext_bytes
        .try_into()
        .map_err(|_| JsValue::from_str("Invalid ciphertext length"))?;

    let ss = sk.decapsulate(&ct).map_err(|_| JsValue::from_str("Decapsulation failed"))?;
    Ok(ss.to_vec())
}

// ──────────────────────────────────────────────────────────────
// ML-KEM-1024 (Kyber-1024 equivalent)
// ──────────────────────────────────────────────────────────────

/// Generates a fresh ML-KEM-1024 key pair using OS RNG.
#[wasm_bindgen]
pub fn ml_kem_1024_generate_keypair() -> Result<KemKeyPair, JsValue> {
    let (sk, pk) = MlKem1024::generate(&mut OsRng);
    Ok(KemKeyPair {
        public_key: pk.as_bytes().to_vec(),
        secret_key: sk.as_bytes().to_vec(),
    })
}

/// Performs ML-KEM-1024 encapsulation.
#[wasm_bindgen]
pub fn ml_kem_1024_encapsulate(public_key_bytes: &[u8]) -> Result<CiphertextAndSharedSecret, JsValue> {
    let enc_pk: Encoded<EncapsulationKey<MlKem1024Params>> = public_key_bytes
        .try_into()
        .map_err(|_| JsValue::from_str("Invalid public key length"))?;
    let pk = EncapsulationKey::<MlKem1024Params>::from_bytes(&enc_pk);

    let (ct, ss) = pk.encapsulate(&mut OsRng).map_err(|_| JsValue::from_str("Encapsulation failed"))?;

    Ok(CiphertextAndSharedSecret {
        ciphertext: ct.to_vec(),
        shared_secret: ss.to_vec(),
    })
}

/// Performs ML-KEM-1024 decapsulation.
#[wasm_bindgen]
pub fn ml_kem_1024_decapsulate(secret_key_bytes: &[u8], ciphertext_bytes: &[u8]) -> Result<Vec<u8>, JsValue> {
    let enc_sk: Encoded<DecapsulationKey<MlKem1024Params>> = secret_key_bytes
        .try_into()
        .map_err(|_| JsValue::from_str("Invalid secret key length"))?;
    let sk = DecapsulationKey::<MlKem1024Params>::from_bytes(&enc_sk);

    let ct: KemCiphertext<MlKem1024> = ciphertext_bytes
        .try_into()
        .map_err(|_| JsValue::from_str("Invalid ciphertext length"))?;

    let ss = sk.decapsulate(&ct).map_err(|_| JsValue::from_str("Decapsulation failed"))?;
    Ok(ss.to_vec())
}

// ──────────────────────────────────────────────────────────────
// ML-KEM convenience aliases (currently ML-KEM-768)
// ──────────────────────────────────────────────────────────────

/// Alias: generate ML-KEM-768 key pair
#[wasm_bindgen]
pub fn kem_generate_keypair() -> Result<KemKeyPair, JsValue> {
    ml_kem_768_generate_keypair()
}

/// Alias: encapsulate using ML-KEM-768 public key
#[wasm_bindgen]
pub fn kem_encapsulate(public_key_bytes: &[u8]) -> Result<CiphertextAndSharedSecret, JsValue> {
    ml_kem_768_encapsulate(public_key_bytes)
}

/// Alias: decapsulate using ML-KEM-768 secret key + ciphertext
#[wasm_bindgen]
pub fn kem_decapsulate(secret_key_bytes: &[u8], ciphertext_bytes: &[u8]) -> Result<Vec<u8>, JsValue> {
    ml_kem_768_decapsulate(secret_key_bytes, ciphertext_bytes)
}

// ──────────────────────────────────────────────────────────────
// ML-DSA-44 (Dilithium2 equivalent)
// ──────────────────────────────────────────────────────────────

/// Generates a fresh ML-DSA-44 key pair.
#[wasm_bindgen]
pub fn ml_dsa_44_generate_keypair() -> Result<DsaKeyPair, JsValue> {
    let kp = MlDsa44::key_gen(&mut OsRng);
    Ok(DsaKeyPair {
        public_key: kp.verifying_key().encode().to_vec(),
        secret_key: kp.signing_key().encode().to_vec(),
    })
}

/// Signs a message using an ML-DSA-44 secret key.
#[wasm_bindgen]
pub fn ml_dsa_44_sign(secret_key_bytes: &[u8], message: &[u8]) -> Result<Vec<u8>, JsValue> {
    let enc_sk: EncodedSigningKey<MlDsa44> = secret_key_bytes
        .try_into()
        .map_err(|_| JsValue::from_str("Invalid secret key length"))?;
    let sk = SigningKey::<MlDsa44>::decode(&enc_sk);
    let sig = sk.sign(message);
    Ok(sig.encode().to_vec())
}

/// Verifies an ML-DSA-44 signature against a message and public key.
#[wasm_bindgen]
pub fn ml_dsa_44_verify(public_key_bytes: &[u8], message: &[u8], signature_bytes: &[u8]) -> Result<bool, JsValue> {
    let enc_pk: EncodedVerifyingKey<MlDsa44> = public_key_bytes
        .try_into()
        .map_err(|_| JsValue::from_str("Invalid public key length"))?;
    let pk = VerifyingKey::<MlDsa44>::decode(&enc_pk);

    let enc_sig: EncodedSignature<MlDsa44> = signature_bytes
        .try_into()
        .map_err(|_| JsValue::from_str("Invalid signature length"))?;
    let sig = Signature::<MlDsa44>::decode(&enc_sig).ok_or_else(|| JsValue::from_str("Invalid signature encoding"))?;

    Ok(pk.verify(message, &sig).is_ok())
}

// ──────────────────────────────────────────────────────────────
// ML-DSA-65 (Dilithium3 equivalent) — default recommendation
// ──────────────────────────────────────────────────────────────

/// Generates a fresh ML-DSA-65 key pair.
#[wasm_bindgen]
pub fn ml_dsa_65_generate_keypair() -> Result<DsaKeyPair, JsValue> {
    let kp = MlDsa65::key_gen(&mut OsRng);
    Ok(DsaKeyPair {
        public_key: kp.verifying_key().encode().to_vec(),
        secret_key: kp.signing_key().encode().to_vec(),
    })
}

/// Signs a message using an ML-DSA-65 secret key.
#[wasm_bindgen]
pub fn ml_dsa_65_sign(secret_key_bytes: &[u8], message: &[u8]) -> Result<Vec<u8>, JsValue> {
    let enc_sk: EncodedSigningKey<MlDsa65> = secret_key_bytes
        .try_into()
        .map_err(|_| JsValue::from_str("Invalid secret key length"))?;
    let sk = SigningKey::<MlDsa65>::decode(&enc_sk);
    let sig = sk.sign(message);
    Ok(sig.encode().to_vec())
}

/// Verifies an ML-DSA-65 signature.
#[wasm_bindgen]
pub fn ml_dsa_65_verify(public_key_bytes: &[u8], message: &[u8], signature_bytes: &[u8]) -> Result<bool, JsValue> {
    let enc_pk: EncodedVerifyingKey<MlDsa65> = public_key_bytes
        .try_into()
        .map_err(|_| JsValue::from_str("Invalid public key length"))?;
    let pk = VerifyingKey::<MlDsa65>::decode(&enc_pk);

    let enc_sig: EncodedSignature<MlDsa65> = signature_bytes
        .try_into()
        .map_err(|_| JsValue::from_str("Invalid signature length"))?;
    let sig = Signature::<MlDsa65>::decode(&enc_sig).ok_or_else(|| JsValue::from_str("Invalid signature encoding"))?;

    Ok(pk.verify(message, &sig).is_ok())
}

// ──────────────────────────────────────────────────────────────
// ML-DSA-87 (Dilithium5 equivalent)
// ──────────────────────────────────────────────────────────────

/// Generates a fresh ML-DSA-87 key pair.
#[wasm_bindgen]
pub fn ml_dsa_87_generate_keypair() -> Result<DsaKeyPair, JsValue> {
    let kp = MlDsa87::key_gen(&mut OsRng);
    Ok(DsaKeyPair {
        public_key: kp.verifying_key().encode().to_vec(),
        secret_key: kp.signing_key().encode().to_vec(),
    })
}

/// Signs a message using an ML-DSA-87 secret key.
#[wasm_bindgen]
pub fn ml_dsa_87_sign(secret_key_bytes: &[u8], message: &[u8]) -> Result<Vec<u8>, JsValue> {
    let enc_sk: EncodedSigningKey<MlDsa87> = secret_key_bytes
        .try_into()
        .map_err(|_| JsValue::from_str("Invalid secret key length"))?;
    let sk = SigningKey::<MlDsa87>::decode(&enc_sk);
    let sig = sk.sign(message);
    Ok(sig.encode().to_vec())
}

/// Verifies an ML-DSA-87 signature.
#[wasm_bindgen]
pub fn ml_dsa_87_verify(public_key_bytes: &[u8], message: &[u8], signature_bytes: &[u8]) -> Result<bool, JsValue> {
    let enc_pk: EncodedVerifyingKey<MlDsa87> = public_key_bytes
        .try_into()
        .map_err(|_| JsValue::from_str("Invalid public key length"))?;
    let pk = VerifyingKey::<MlDsa87>::decode(&enc_pk);

    let enc_sig: EncodedSignature<MlDsa87> = signature_bytes
        .try_into()
        .map_err(|_| JsValue::from_str("Invalid signature length"))?;
    let sig = Signature::<MlDsa87>::decode(&enc_sig).ok_or_else(|| JsValue::from_str("Invalid signature encoding"))?;

    Ok(pk.verify(message, &sig).is_ok())
}

// ──────────────────────────────────────────────────────────────
// ML-DSA convenience aliases (currently ML-DSA-65)
// ──────────────────────────────────────────────────────────────

/// Alias: generate ML-DSA-65 key pair (current default security level)
#[wasm_bindgen]
pub fn dsa_generate_keypair() -> Result<DsaKeyPair, JsValue> {
    ml_dsa_65_generate_keypair()
}

/// Alias: sign with ML-DSA-65
#[wasm_bindgen]
pub fn dsa_sign(secret_key_bytes: &[u8], message: &[u8]) -> Result<Vec<u8>, JsValue> {
    ml_dsa_65_sign(secret_key_bytes, message)
}

/// Alias: verify with ML-DSA-65
#[wasm_bindgen]
pub fn dsa_verify(public_key_bytes: &[u8], message: &[u8], signature_bytes: &[u8]) -> Result<bool, JsValue> {
    ml_dsa_65_verify(public_key_bytes, message, signature_bytes)
}

// ──────────────────────────────────────────────────────────────
// Argon2id password hashing
// ──────────────────────────────────────────────────────────────

/// Hashes a password using Argon2id (v=0x13, default/recommended parameters) and returns PHC string.
///
/// Suitable for password storage. Includes random salt.
#[wasm_bindgen]
pub fn argon2id_hash(password: &[u8]) -> Result<String, JsValue> {
    let argon2 = Argon2::default();
    let salt = argon2::password_hash::phc::Salt::generate();
    let phc = argon2
        .hash_password_with_salt(password, &salt)
        .map_err(|e| JsValue::from_str(&format!("Argon2 hash failed: {e}")))?;
    Ok(phc.to_string())
}

/// Verifies that the provided password matches the stored PHC hash string.
///
/// Returns `true` if the password is correct.
#[wasm_bindgen]
pub fn argon2_verify(password: &[u8], phc: &str) -> Result<bool, JsValue> {
    let argon2 = Argon2::default();
    let parsed = PasswordHash::new(phc)
        .map_err(|e| JsValue::from_str(&format!("Invalid PHC string: {e}")))?;
    Ok(argon2.verify_password(password, &parsed).is_ok())
}