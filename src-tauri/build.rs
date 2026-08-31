fn main() {
    // Tauri embeds the Common-Controls v6 manifest via embed-resource's
    // compile(), which only links into [[bin]] targets. The cargo test
    // harness for the lib then loads legacy comctl32 v5 and dies at process
    // start with STATUS_ENTRYPOINT_NOT_FOUND (0xc0000139) on Windows.
    // Upstream: tauri-apps/tauri#13419. Link the dependency for every
    // artifact so CI `cargo test` can run on windows-2022.
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let target_env = std::env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();
    if target_os == "windows" && target_env == "msvc" {
        let manifest =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("windows-app-manifest.xml");
        println!("cargo:rerun-if-changed={}", manifest.display());
        println!("cargo:rustc-link-arg=/MANIFEST:EMBED");
        println!("cargo:rustc-link-arg=/MANIFESTINPUT:{}", manifest.display());
        // Drop tauri-build's bins-only resource manifest so it is not
        // duplicated with the linker-embedded copy.
        let windows = tauri_build::WindowsAttributes::new_without_app_manifest();
        let attrs = tauri_build::Attributes::new().windows_attributes(windows);
        tauri_build::try_build(attrs).expect("failed to run tauri-build");
        return;
    }

    tauri_build::build()
}
