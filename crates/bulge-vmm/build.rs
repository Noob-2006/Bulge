// Link against libkrun. BULGE_LIBKRUN_DIR overrides the default ~/.local/lib.
fn main() {
    println!("cargo:rerun-if-env-changed=BULGE_LIBKRUN_DIR");
    let dir = std::env::var("BULGE_LIBKRUN_DIR")
        .unwrap_or_else(|_| format!("{}/.local/lib", std::env::var("HOME").unwrap_or_default()));
    println!("cargo:rustc-link-search=native={dir}");
    println!("cargo:rustc-link-arg=-Wl,-rpath,{dir}");
    println!("cargo:rustc-link-lib=dylib=krun");
}
