//! Fingerprints the shader translator, so that cached translations
//! (`src/shader_cache.rs`) last until the translator itself changes and not
//! only until the next build of anything.

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rustc-env=SCARLETT_TRANSLATOR=0cd0c36ab2672431e7c817f40d9e442867c7224cfa18a7b31c2d216470d515d2");
}
