use std::{env, ffi::OsStr, path::PathBuf};

use anyhow::Result;
use grev::git_revision_auto;
use libbpf_cargo::SkeletonBuilder;

const SRC: &str = "src/bpf/past.bpf.c";

fn main() -> Result<()> {
    let out = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR must be set in build script")).join("past.skel.rs");

    let arch = env::var("CARGO_CFG_TARGET_ARCH").expect("CARGO_CFG_TARGET_ARCH must be set in build script");
    let mut builder = SkeletonBuilder::new();
    if let Some(clang) = option_env!("CLANG") {
        builder.clang(clang);
    }
    builder
        .source(SRC)
        .clang_args([OsStr::new("-I"), vmlinux::include_path_root().join(arch).as_os_str()])
        .build_and_generate(&out)?;
    println!("cargo:rerun-if-changed={SRC}");

    let dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    if let Some(git_rev) = git_revision_auto(dir)? {
        println!("cargo:rustc-env=VERSION={} ({})", env!("CARGO_PKG_VERSION"), git_rev);
    } else {
        println!("cargo:rustc-env=VERSION={}", env!("CARGO_PKG_VERSION"));
    }
    Ok(())
}
