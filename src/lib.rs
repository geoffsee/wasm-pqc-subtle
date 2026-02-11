use wasm_bindgen::prelude::*;
use ml_kem::{MlKem768, MlKem768Params, MlKem1024, MlKem1024Params, KemCore, Encoded, EncodedSizeUser};
use ml_kem::kem::{EncapsulationKey, DecapsulationKey, Encapsulate, Decapsulate};
use rand_core::OsRng;
use ml_kem::Ciphertext as KemCiphertext;

#[wasm_bindgen]
pub struct KemKeyPair {
    public_key: Vec<u8>,
    secret_key: Vec<u8>,
}

#[wasm_bindgen]
impl KemKeyPair {
    #[wasm_bindgen(getter)]
    pub fn public_key(&self) -> Vec<u8> {
        self.public_key.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn secret_key(&self) -> Vec<u8> {
        self.secret_key.clone()
    }
}

#[wasm_bindgen]
pub struct CiphertextAndSharedSecret {
    ciphertext: Vec<u8>,
    shared_secret: Vec<u8>,
}

#[wasm_bindgen]
impl CiphertextAndSharedSecret {
    #[wasm_bindgen(getter)]
    pub fn ciphertext(&self) -> Vec<u8> {
        self.ciphertext.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn shared_secret(&self) -> Vec<u8> {
        self.shared_secret.clone()
    }
}

#[wasm_bindgen]
pub fn ml_kem_768_generate_keypair() -> Result<KemKeyPair, JsValue> {
    let (sk, pk) = MlKem768::generate(&mut OsRng);
    Ok(KemKeyPair {
        public_key: pk.as_bytes().to_vec(),
        secret_key: sk.as_bytes().to_vec(),
    })
}

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

#[wasm_bindgen]
pub fn ml_kem_1024_generate_keypair() -> Result<KemKeyPair, JsValue> {
    let (sk, pk) = MlKem1024::generate(&mut OsRng);
    Ok(KemKeyPair {
        public_key: pk.as_bytes().to_vec(),
        secret_key: sk.as_bytes().to_vec(),
    })
}

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

#[wasm_bindgen]
pub fn kem_generate_keypair() -> Result<KemKeyPair, JsValue> {
    ml_kem_768_generate_keypair()
}

#[wasm_bindgen]
pub fn kem_encapsulate(public_key_bytes: &[u8]) -> Result<CiphertextAndSharedSecret, JsValue> {
    ml_kem_768_encapsulate(public_key_bytes)
}

#[wasm_bindgen]
pub fn kem_decapsulate(secret_key_bytes: &[u8], ciphertext_bytes: &[u8]) -> Result<Vec<u8>, JsValue> {
    ml_kem_768_decapsulate(secret_key_bytes, ciphertext_bytes)
}

