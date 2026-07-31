fn main() {
    // Linker flags for WASM size; do not pass GNU-only flags to native linkers.
    let target = std::env::var("TARGET").unwrap_or_default();
    if target.contains("wasm32") {
        println!("cargo:rustc-link-arg=--strip-all");
    }
}
