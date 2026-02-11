# wasm-pqc-subtle

Post-quantum key encapsulation for the browser. A WebAssembly library implementing [ML-KEM](https://csrc.nist.gov/pubs/fips/203/final) (FIPS 203) for secure key establishment, compiled from Rust.

## Overview

This library provides ML-KEM-768 and ML-KEM-1024 key encapsulation via WebAssembly, enabling post-quantum key exchange in web applications. It wraps the [`ml-kem`](https://crates.io/crates/ml-kem) Rust crate using [`wasm-bindgen`](https://crates.io/crates/wasm-bindgen) and targets the `wasm32-unknown-unknown` platform.

**WASM binary size:** ~68 KB (optimized with LTO + binaryen)

### Supported Algorithms

| Algorithm | NIST Security Level | Use Case |
|-----------|-------------------|----------|
| ML-KEM-768 | Level 3 (~192-bit) | Default. Recommended for most applications. |
| ML-KEM-1024 | Level 5 (~256-bit) | Higher security margin. |

## Installation

```bash
npm install wasm-pqc-subtle
```

## Usage

```javascript
import init, {
  ml_kem_768_generate_keypair,
  ml_kem_768_encapsulate,
  ml_kem_768_decapsulate,
} from "wasm-pqc-subtle";

await init();

// Generate a keypair
const keypair = ml_kem_768_generate_keypair();

// Encapsulate: produce a ciphertext and shared secret from the public key
const result = ml_kem_768_encapsulate(keypair.public_key);

// Decapsulate: recover the shared secret from the ciphertext and secret key
const sharedSecret = ml_kem_768_decapsulate(keypair.secret_key, result.ciphertext);

// result.shared_secret and sharedSecret are identical
```

ML-KEM-1024 functions follow the same pattern (`ml_kem_1024_generate_keypair`, etc.). Convenience aliases `kem_generate_keypair`, `kem_encapsulate`, and `kem_decapsulate` default to ML-KEM-768.

## API

### `ml_kem_768_generate_keypair() -> KemKeyPair`

Generates an ML-KEM-768 key pair.

### `ml_kem_768_encapsulate(public_key: Uint8Array) -> CiphertextAndSharedSecret`

Encapsulates against a public key, returning a ciphertext and shared secret.

### `ml_kem_768_decapsulate(secret_key: Uint8Array, ciphertext: Uint8Array) -> Uint8Array`

Decapsulates a ciphertext with a secret key, returning the shared secret.

### `ml_kem_1024_generate_keypair()` / `ml_kem_1024_encapsulate()` / `ml_kem_1024_decapsulate()`

Same interface as above, using ML-KEM-1024 parameters.

### `kem_generate_keypair()` / `kem_encapsulate()` / `kem_decapsulate()`

Convenience aliases that use ML-KEM-768.

### Types

```typescript
class KemKeyPair {
  readonly public_key: Uint8Array;
  readonly secret_key: Uint8Array;
}

class CiphertextAndSharedSecret {
  readonly ciphertext: Uint8Array;
  readonly shared_secret: Uint8Array;
}
```

## Building from Source

### Prerequisites

- [Rust](https://rustup.rs/)
- [wasm-pack](https://rustwasm.github.io/wasm-pack/installer/)
- [binaryen](https://github.com/WebAssembly/binaryen) (for `wasm-opt`)

### Build

```bash
make all
```

This runs `wasm-pack build --target web --release` followed by `wasm-opt -Oz` for size optimization. Output goes to `./pkg/`.

### Test

Open `index.html` in a browser (served over HTTP) to run the ML-KEM-768 and ML-KEM-1024 test suite.

### Publish

```bash
make publish
```

## Export Control Notice

This software implements cryptographic functionality and is subject to export controls.

**ECCN:** 5D002 — This software is classified under Export Control Classification Number 5D002 ("Information Security" software) on the Commerce Control List (CCL).

**License Exception:** This software is publicly available open-source encryption source code, distributed under License Exception TSU (Technology and Software Unrestricted) pursuant to 15 CFR 740.13(e) of the U.S. Export Administration Regulations (EAR). The compiled WebAssembly binary is distributed under License Exception ENC pursuant to 15 CFR 740.17(b).

**Notification:** In accordance with 15 CFR 742.15(b), a notification has been or should be submitted to the Bureau of Industry and Security (crypt@bis.gov) and the ENC Encryption Request Coordinator (enc@nsa.gov) prior to or concurrent with the first public release of this software.

**Restrictions:** This software may not be exported or re-exported to any country in U.S. Country Group E:1 (currently Cuba, Iran, North Korea, Syria, and the Crimea/Donetsk/Luhansk regions of Ukraine) or to any person or entity on the BIS Denied Persons List, Entity List, or Unverified List.

**International:** Users outside the United States should be aware that similar controls may apply under the Wassenaar Arrangement, EU Dual-Use Regulation (EU 2021/821), and other national export control regimes. The Wassenaar Arrangement's General Software Note provides decontrol for software that is "in the public domain," though implementation varies by jurisdiction.

**This is not legal advice.** Export control regulations are complex and subject to change. Consult a qualified export control attorney for compliance guidance specific to your circumstances.

## License

See repository for license terms.
