extern crate prost_build;

use std::env;

use anyhow::Result;
use grev::git_revision_auto;

fn main() -> Result<()> {
    prost_build::Config::new()
        .out_dir("src/proto/")
        .compile_protos(&["src/proto/profile.proto"], &["src/proto/"])?;

    let dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    if let Some(git_rev) = git_revision_auto(dir)? {
        println!("cargo:rustc-env=VERSION={} ({})", env!("CARGO_PKG_VERSION"), git_rev);
    } else {
        println!("cargo:rustc-env=VERSION={}", env!("CARGO_PKG_VERSION"));
    }
    Ok(())
}
