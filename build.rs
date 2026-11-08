const COMMANDS: &[&str] = &[
    "get_passwords",
    "set_passwords",
    "delete_passwords",
    "password_exists",
    "export_passwords_plain",
    "import_passwords_plain",
    "export_passwords_encrypted",
    "import_passwords_encrypted",
    "ping",
    "initialize",
    "destroy",
    "save",
    "create_client",
    "load_client",
    "get_store_record",
    "save_store_record",
    "remove_store_record",
    "save_secret",
    "remove_secret",
    "execute_procedure",
];

fn main() {
    tauri_plugin::Builder::new(COMMANDS).build();

    // Test binaries link tauri, which needs Common-Controls v6 on Windows:
    // without this manifest they fail to start (STATUS_ENTRYPOINT_NOT_FOUND).
    // Same workaround as tauri's own build.rs. Link args of a build script
    // apply only to this crate's own linked targets (it is an rlib, so its
    // test binaries), never to apps that depend on it.
    let windows = std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows");
    let msvc = std::env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("msvc");
    if windows && msvc {
        let manifest =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("windows-test-manifest.xml");
        println!("cargo:rerun-if-changed={}", manifest.display());
        println!("cargo:rustc-link-arg=/MANIFEST:EMBED");
        println!("cargo:rustc-link-arg=/MANIFESTINPUT:{}", manifest.display());
    }
}
