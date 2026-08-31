use std::env;
use std::ffi::OsString;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=assets/windows/clipferry.rc");
    println!("cargo:rerun-if-changed=assets/brand/clipferry.ico");

    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows")
        || env::var("CARGO_CFG_TARGET_ENV").as_deref() != Ok("msvc")
    {
        return;
    }

    let manifest_directory = PathBuf::from(
        env::var_os("CARGO_MANIFEST_DIR").expect("Cargo must provide CARGO_MANIFEST_DIR"),
    );
    let output_directory =
        PathBuf::from(env::var_os("OUT_DIR").expect("Cargo must provide OUT_DIR to build scripts"));
    let resource_source = manifest_directory.join("assets/windows/clipferry.rc");
    let compiled_resource = output_directory.join("clipferry.res");
    let resource_compiler = env::var_os("RC").unwrap_or_else(|| OsString::from("rc.exe"));

    let status = Command::new(&resource_compiler)
        .current_dir(&manifest_directory)
        .arg("/nologo")
        .arg(format!("/fo{}", compiled_resource.display()))
        .arg(&resource_source)
        .status()
        .unwrap_or_else(|error| {
            panic!(
                "failed to launch the Windows resource compiler {}: {error}",
                PathBuf::from(&resource_compiler).display()
            )
        });
    assert!(status.success(), "Windows resource compilation failed");

    println!(
        "cargo:rustc-link-arg-bin=clipferry={}",
        compiled_resource.display()
    );
}
