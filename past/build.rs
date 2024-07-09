use std::{env, ffi::OsStr, path::PathBuf};

use anyhow::Result;
use grev::git_revision_auto;
use libbpf_cargo::SkeletonBuilder;

const SRC: &str = "src/bpf/past.bpf.c";

fn main() -> Result<()> {
    let out = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR must be set in build script"))
        .join("src")
        .join("bpf")
        .join("past.skel.rs");

    let arch = env::var("CARGO_CFG_TARGET_ARCH").expect("CARGO_CFG_TARGET_ARCH must be set in build script");
    SkeletonBuilder::new()
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
