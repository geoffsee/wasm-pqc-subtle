fn main() {
    // Linker flags for WASM optimization
    // Note: build.rs runs before the crate is compiled.
    // These flags are passed to the linker.
    println!("cargo:rustc-link-arg=--strip-all");
}
