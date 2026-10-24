fn main() {
    // The command palette and the design tokens are shared by both apps; one
    // source of each in ui/, copied into this app's dist/.
    for file in ["palette.js", "theme.css"] {
        let source = std::path::Path::new("../../ui").join(file);
        println!("cargo:rerun-if-changed={}", source.display());
        std::fs::copy(&source, std::path::Path::new("dist").join(file)).unwrap_or_else(|e| panic!("copy {} into dist/: {e}", source.display()));
    }
    tauri_build::build();
}
