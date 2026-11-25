fn main() {
    #[cfg(target_os = "windows")]
    {
        println!("cargo:rustc-link-arg=/EXPORT:D3D12SDKVersion");
        println!("cargo:rustc-link-arg=/EXPORT:D3D12SDKPath");
    }
}
