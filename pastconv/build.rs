extern crate prost_build;

fn main() {
    prost_build::Config::new()
        .out_dir("src/proto/")
        .compile_protos(&["src/proto/profile.proto"], &["src/proto/"])
        .unwrap();
}
